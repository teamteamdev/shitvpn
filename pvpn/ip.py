import struct, ipaddress, os, asyncio, random, heapq, collections, time, enum
from . import enums, dns

SMSS = 1350

def parse_ipv4(data):
    ihl = data[0]&0x0f
    length = int.from_bytes(data[2:4], 'big')
    proto = enums.IpProto(data[9])
    src_ip = ipaddress.ip_address(data[12:16])
    dst_ip = ipaddress.ip_address(data[16:20])
    body = data[ihl<<2:length]
    return proto, src_ip, dst_ip, body

def checksum(data):
    x = sum(struct.unpack(f'>{len(data)//2}H', data))
    while x > 0xffff:
        x = (x>>16)+(x&0xffff)
    x = 65535 - x
    return x.to_bytes(2, 'big')

def make_ipv4(proto, src_ip, dst_ip, body):
    ip_header = bytearray(struct.pack('>BxH2s2xBB2x4s4s', 0x45, len(body)+20, os.urandom(2), 64,
        proto, src_ip.packed, dst_ip.packed))
    ip_header[10:12] = checksum(ip_header)
    return bytes(ip_header+body)

def parse_udp(data):
    src_port, dst_port = struct.unpack('>HH', data[:4])
    return src_port, dst_port, data[8:]

def make_udp(src_port, dst_port, body):
    return struct.pack('>HHHH', src_port, dst_port, len(body)+8, 0)+body

def parse_icmp(data):
    icmptp, code = struct.unpack('>BB', data[:2])
    return icmptp, code, data[8:]

def parse_tcp(data):
    src_port, dst_port = struct.unpack('>HH', data[:4])
    offset = data[12]
    flag = data[13]
    body = data[offset>>2:]
    return src_port, dst_port, flag, body

class State(enum.Enum):
    LISTEN = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_WAIT_1 = 4
    FIN_WAIT_2 = 5
    CLOSE_WAIT = 6
    CLOSING = 7
    LAST_ACK = 8
    TIME_WAIT = 9
    CLOSED = 10
    INITIAL = 100

class Control(enum.IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

class TCPStack:
    def __init__(self, src_ip, src_port, dst_ip, dst_name, dst_port, reply, tcp_conn, verbose):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_name = dst_name
        self.dst_port = dst_port
        self.reply = reply
        self.tcp_conn = tcp_conn
        self.src_seq = 0
        self.dst_seq = self.dst_ack = 0
        self.src_win = []
        self.dst_win = collections.deque()
        self.dst_win_buf = bytearray()
        self.writer = None
        self.state = State.INITIAL
        self.cwnd = 2*SMSS if SMSS>2190 else 3*SMSS if SMSS>1095 else 4*SMSS
        self.rwnd = 65535
        self.ssthresh = 65535
        self.fast_resend = 0
        self.wait_send = asyncio.Event()
        self.wait_ack = asyncio.Event()
        self.wait_fast = asyncio.Event()
        self.rto = 3
        self.srtt = self.rttvar = None
        self.update = time.perf_counter()
        self.verbose = verbose
    def logwrite(self, data):
        if self.verbose >= 2:
            print(f'TCP WRITE {self.dst_name}:{self.dst_port} {data}')
    def logread(self, data):
        if self.verbose >= 2:
            print(f'TCP READ {self.dst_name}:{self.dst_port} {data}')
    def obsolete(self):
        return self.state == State.CLOSED or time.perf_counter() - self.update > 600
    def close(self):
        self.state = State.CLOSED
    def calc_rto(self, r):
        if self.srtt is None:
            self.srtt = r
            self.rttvar = r/2
        else:
            self.rttvar = 0.75*self.rttvar + 0.25*abs(self.srtt-r)
            self.srtt = 0.875*self.srtt + 0.125*r
        self.rto = min(self.srtt + max(0.1, 4*self.rttvar), 60)
    async def retransmit(self):
        while self.state != State.CLOSED:
            if self.dst_seq == self.dst_ack:
                self.wait_ack.clear()
                await self.wait_ack.wait()
            if self.state == State.CLOSED:
                break
            seq = self.dst_ack
            self.wait_fast.clear()
            timeout = False
            try:
                await asyncio.wait_for(self.wait_fast.wait(), self.rto)
            except asyncio.TimeoutError:
                timeout = True
            if self.state == State.CLOSED:
                break
            if seq != self.dst_ack:
                continue
            # retransmit
            #print('retransmit', self.dst_ip, self.dst_port, self.dst_ack, self.dst_seq, len(self.dst_win_buf), self.rto, timeout)
            flag = None
            if self.dst_win:
                self.dst_win[0][3] = 0
                if self.dst_win[0][0] == self.dst_ack and self.dst_win[0][2] == 1:
                    flag = self.dst_win_buf[0]
            if flag is not None:
                self.send(seq=self.dst_ack, flag=flag)
            else:
                tcp_body = self.dst_win_buf[:SMSS]
                self.send(tcp_body, seq=self.dst_ack)
            if timeout:
                self.rto = min(self.rto*2, 60)
                self.ssthresh = max((self.dst_seq-self.dst_ack)//2, 2*SMSS)
                self.cwnd = self.ssthresh+3*SMSS
    def parse(self, ip_body):
        src_port, dst_port, seq, ack, offset, flag, window = struct.unpack('>HHIIBBH', ip_body[:16])
        tcp_body = ip_body[offset>>2:]
        self.rwnd = window
        self.update = time.perf_counter()
        # print('RECV', self.dst_name, self.dst_port, self.state, Control(flag), seq, ack, len(tcp_body))
        if self.state == State.CLOSED:
            if flag & Control.RST:
                pass
            elif flag & Control.ACK:
                self.send(seq=ack, flag=Control.RST)
            else:
                self.send(seq=0, ack=seq+len(tcp_body), flag=Control.RST|Control.ACK)
        elif self.state == State.INITIAL:
            if flag & Control.RST:
                pass
            elif flag & Control.ACK:
                self.send(seq=ack, flag=Control.RST)
            elif flag & Control.SYN:
                self.state = State.SYN_RECEIVED
                self.src_seq = seq+1
                self.dst_seq = self.dst_ack = random.randrange(0x100000000)
                asyncio.ensure_future(self.connect())
                asyncio.ensure_future(self.retransmit())
        elif flag & Control.RST:
            self.close()
            self.wait_ack.set()
            self.wait_send.set()
            try:
                self.writer.close()
            except Exception:
                pass
        elif flag & Control.SYN:
            pass
        elif flag & Control.ACK == 0:
            pass
        else:
            if self.state == State.SYN_RECEIVED:
                self.state = State.ESTABLISHED
            while self.dst_ack-ack > 0x20000000:
                ack += 0x100000000
            if self.dst_ack < self.dst_seq:
                diff_ack = ack-self.dst_ack
                if diff_ack == 0 and not tcp_body:
                    self.fast_resend += 1
                    if self.fast_resend < 3:
                        self.wait_send.set()
                    elif self.fast_resend == 3:
                        self.wait_fast.set()
                    else:
                        self.cwnd += SMSS
                if diff_ack > 0:
                    self.fast_resend = 0
                    counter = 0
                    while self.dst_win and self.dst_win[0][0]+self.dst_win[0][1] <= ack:
                        seq, length, tp, counter = self.dst_win.popleft()
                    del self.dst_win_buf[:diff_ack]
                    self.dst_ack = ack
                    self.wait_fast.set()
                    if self.dst_seq-self.dst_ack <= min(self.cwnd, self.rwnd):
                        self.wait_send.set()
                    if self.cwnd < self.ssthresh:
                        self.cwnd += min(diff_ack, SMSS)
                    else:
                        self.cwnd += SMSS*SMSS//self.cwnd
                    if counter == 0:
                        self.cwnd = self.ssthresh
                    if counter > 0:
                        time_diff = time.perf_counter() - counter
                        self.calc_rto(time_diff)
            if self.state == State.FIN_WAIT_1:
                if self.dst_ack >= self.dst_seq:
                    self.state = State.FIN_WAIT_2
            if tcp_body and self.state in (State.ESTABLISHED, State.FIN_WAIT_1, State.FIN_WAIT_2):
                while self.src_seq-seq > 0x20000000:
                    seq += 0x100000000
                if seq+len(tcp_body) <= self.src_seq:
                    pass
                elif seq <= self.src_seq:
                    self.logwrite(tcp_body[self.src_seq-seq:])
                    self.writer.write(tcp_body[self.src_seq-seq:])
                    self.src_seq = seq+len(tcp_body)
                    while self.src_win and self.src_win[0][0] <= self.src_seq:
                        seq, tcp_body = heapq.heappop(self.src_win)
                        if seq+len(tcp_body) > self.src_seq:
                            self.logwrite(tcp_body[self.src_seq-seq:])
                            self.writer.write(tcp_body[self.src_seq-seq:])
                            self.src_seq = seq+len(tcp_body)
                elif seq-self.src_seq < 0x20000000:
                    heapq.heappush(self.src_win, (seq, tcp_body))
                self.send()
            if flag & Control.FIN:
                while self.src_seq-seq > 0x20000000:
                    seq += 0x100000000
                if seq+1 <= self.src_seq:
                    pass
                elif seq <= self.src_seq:
                    self.src_seq = seq+1
                    self.send()
                    if self.state in (State.SYN_RECEIVED, State.ESTABLISHED):
                        self.state = State.CLOSE_WAIT
                        try:
                            self.writer.close()
                        except Exception:
                            pass
                    elif self.state == State.FIN_WAIT_2:
                        self.close()
                        self.wait_ack.set()
    def send(self, tcp_body=b'', *, flag=Control.ACK, seq=None, ack=None):
        self.update = time.perf_counter()
        window = max(0, (65535-len(self.writer.transport._buffer)) if self.writer else 0)
        # print('SEND', self.dst_name, self.dst_port, self.state, Control(flag), (self.dst_seq if seq is None else seq), (self.src_seq if ack is None else ack), len(tcp_body))
        tcp_header = struct.pack('>HHIIBBHHH', self.dst_port, self.src_port, (self.dst_seq if seq is None else seq)&0xffffffff, (self.src_seq if ack is None else ack)&0xffffffff, 5<<4, flag, window, 0, 0)
        ip_body = bytearray(tcp_header + tcp_body)
        tochecksum = bytearray(self.dst_ip.packed+self.src_ip.packed+b'\x00\x06'+len(ip_body).to_bytes(2, 'big') + ip_body)
        if len(tochecksum) % 2 == 1:
            tochecksum.extend(b'\x00')
        ip_body[16:18] = checksum(tochecksum)
        data = make_ipv4(6, self.dst_ip, self.src_ip, ip_body)
        if not self.reply(data):
            self.close()
            self.wait_ack.set()
            self.wait_send.set()
            try:
                self.writer.close()
            except Exception:
                pass
    async def connect(self):
        # print(f'connect {self.dst_ip}:{self.dst_port}')
        total = 0
        try:
            reader, self.writer = await self.tcp_conn.tcp_connect(self.dst_name, self.dst_port)
        except Exception:
            # connect fail
            self.close()
            self.wait_ack.set()
            self.send(flag=Control.RST)
            return
        self.send(flag=Control.ACK|Control.SYN)
        self.dst_win.append([self.dst_seq, 1, 1, time.perf_counter()])
        self.dst_win_buf.extend(bytes([Control.ACK|Control.SYN]))
        self.dst_seq += 1
        self.wait_ack.set()
        while True:
            try:
                data = await reader.read(65536)
            except Exception:
                data = None
            if not data:
                break
            self.logread(data)
            # print(f'TCP READ {self.dst_name}:{self.dst_port} {data}')
            data = bytearray(data)
            while data:
                if self.dst_seq-self.dst_ack > min(self.cwnd, self.rwnd):
                    self.wait_send.clear()
                    await self.wait_send.wait()
                    if self.state == State.CLOSED:
                        break
                tcp_body = data[:SMSS]
                del data[:SMSS]
                total += len(tcp_body)
                self.send(tcp_body)
                self.dst_win.append([self.dst_seq, len(tcp_body), 0, time.perf_counter()])
                self.dst_win_buf.extend(tcp_body)
                self.dst_seq += len(tcp_body)
                self.wait_ack.set()
        if self.state == State.CLOSE_WAIT:
            self.send(flag=Control.ACK|Control.FIN)
            self.dst_win_buf.extend(bytes([Control.ACK|Control.FIN]))
            self.dst_seq += 1
            self.wait_ack.set()
            self.close()
        elif self.state != State.CLOSED:
            self.send(flag=Control.ACK|Control.FIN)
            self.state = State.FIN_WAIT_1
            self.dst_win_buf.extend(bytes([Control.ACK|Control.FIN]))
            self.dst_seq += 1

class IPPacket:
    def __init__(self, args):
        self.tcp_stack = {}
        self.dns_server = args.dns
        self.dns_cache = None if args.nocache else dns.DNSCache()
        self.salgorithm = args.salgorithm
        self.rserver = args.rserver
        self.urserver = args.urserver
        self.DIRECT = args.DIRECT
        self.verbose = args.v if args.v else 0

    def schedule(self, host_name, port, udp=False):
        rserver = self.urserver if udp else self.rserver
        filter_cond = lambda o: o.alive and o.match_rule(host_name, port)
        if self.salgorithm == 'fa':
            return next(filter(filter_cond, rserver), None)
        elif self.salgorithm == 'rr':
            for i, roption in enumerate(rserver):
                if filter_cond(roption):
                    rserver.append(rserver.pop(i))
                    return roption
        elif self.salgorithm == 'rc':
            filters = [i for i in rserver if filter_cond(i)]
            return random.choice(filters) if filters else None
        elif self.salgorithm == 'lc':
            return min(filter(filter_cond, rserver), default=None, key=lambda i: i.total)
        else:
            raise Exception('Unknown scheduling algorithm') #Unreachable

    def handle_ipv4(self, remote_id, data, reply):
        proto, src_ip, dst_ip, ip_body = parse_ipv4(data)
        dst_name = self.dns_cache.ip2domain(str(dst_ip)) if self.dns_cache else str(dst_ip)
        if proto == enums.IpProto.UDP:
            src_port, dst_port, udp_body = parse_udp(ip_body)
            option = self.schedule(dst_name, dst_port, udp=True) or self.DIRECT
            key = (remote_id[0], remote_id[1], src_port)
            if dst_port == 53:
                try:
                    record = dns.DNSRecord.unpack(udp_body)
                    answer = self.dns_cache.query(record) if self.dns_cache else None
                    if self.verbose:
                        print(f'DNS {remote_id[0]}:{src_port}{option.logtext(dst_name, dst_port)} Query={record.q.qname}{" (Cached)" if answer else ""}')
                    if answer:
                        ip_body = make_udp(dst_port, src_port, answer.pack())
                        data = make_ipv4(proto, dst_ip, src_ip, ip_body)
                        reply(data)
                        return
                except Exception as e:
                    print(e)
            else:
                if self.verbose:
                    print(f'UDP {remote_id[0]}:{src_port}{option.logtext(dst_name, dst_port)} Length={len(udp_body)}')
            def udp_reply(udp_body):
                if dst_port == 53:
                    record = dns.DNSRecord.unpack(udp_body)
                    self.dns_cache.answer(record) if self.dns_cache else None
                    if self.verbose:
                        print(f'DNS {remote_id[0]}:{src_port}{option.logtext(dst_name, dst_port).replace("->","<-")} Answer=['+' '.join(f'{r.rname}->{r.rdata}' for r in record.rr)+']')
                else:
                    if self.verbose:
                        print(f'UDP {remote_id[0]}:{src_port}{option.logtext(dst_name, dst_port).replace("->","<-")} Length={len(udp_body)}')
                ip_body = make_udp(dst_port, src_port, udp_body)
                data = make_ipv4(proto, dst_ip, src_ip, ip_body)
                reply(data)
            asyncio.ensure_future(option.udp_sendto(dst_name, dst_port, udp_body, udp_reply, key))
        elif proto == enums.IpProto.TCP:
            src_port, dst_port, flag, tcp_body = parse_tcp(ip_body)
            key = (remote_id[0], remote_id[1], src_port)
            tcp = self.tcp_stack.get(key)
            if tcp is None:
                if flag & Control.SYN == 0:
                    return
                option = self.schedule(dst_name, dst_port) or self.DIRECT
                print(f'TCP {remote_id[0]}:{src_port}{option.logtext(dst_name, dst_port)}')
                for spi, tcp in list(self.tcp_stack.items()):
                    if tcp.obsolete():
                        self.tcp_stack.pop(spi)
                self.tcp_stack[key] = tcp = TCPStack(src_ip, src_port, dst_ip, dst_name, dst_port, reply, option, self.verbose)
                #print(f'TCP Connections = {len(self.tcp_stack)}')
            tcp.parse(ip_body)
        elif proto == enums.IpProto.ICMP:
            icmptp, code, icmp_body = parse_icmp(ip_body)
            if icmptp == 0:
                tid, seq = struct.unpack('>HH', ip_body[4:8])
                if self.verbose:
                    print(f'PING {remote_id[0]} -> {dst_name} Id={tid} Seq={seq} Data={icmp_body}')
            elif icmptp == 8:
                tid, seq = struct.unpack('>HH', ip_body[4:8])
                if self.verbose:
                    print(f'ECHO {remote_id[0]} -> {dst_name} Id={tid} Seq={seq} Data={icmp_body}')
                # NEED ROOT PRIVILEGE TO SEND ICMP PACKET
                # a = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                # a.sendto(icmp_body, (dst_name, 1))
                # a.close()
            elif icmptp == 3 and code == 3:
                eproto, esrc_ip, edst_ip, eip_body = parse_ipv4(icmp_body)
                eport = int.from_bytes(eip_body[2:4], 'big')
                if self.verbose:
                    print(f'ICMP {remote_id[0]} -> {dst_name} {eproto.name} :{eport} Denied')
            else:
                if self.verbose:
                    print(f'ICMP {remote_id[0]} -> {dst_name} Data={ip_body}')
        else:
            print(f'{enums.IpProto(proto).name} -> {dst_name} Data={data}')
