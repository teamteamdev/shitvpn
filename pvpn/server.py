import argparse, asyncio, os, struct, hashlib, base64, itertools, hmac
import pproxy
from . import crypto, ip

ACCEPTED_KEYS = [
    b"\x80P\xddyq\xc2 Q\x18\xe6\xde\x13\x9fq\x13\x89\x96\xda\xfcIB\xc4B#\xd5o0_\xf6\x05TN"
]


class WIREGUARD(asyncio.DatagramProtocol):
    def __init__(self, args):
        self.preshared_key = b'\x00'*32
        self.ippacket = ip.IPPacket(args)
        self.private_key = b"P\x1a\xe4\xb1\x1b\xc1\xb5\xa4s\xd1}\xf7\x13\xb7\xef5\xde7yp\xbfJ\x9c\r\xb0\x0f0(\x04\xd5\x03|"
        self.public_key = crypto.X25519(self.private_key, 9)
        self.keys = {}
        self.index_generators = {}
        self.sender_index_generator = itertools.count()
        print('PublicKey:', base64.b64encode(self.public_key).decode())

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            cmd = int.from_bytes(data[0:4], 'little')
            if cmd == 1 and len(data) == 148:
                HASH = lambda x: hashlib.blake2s(x).digest()
                MAC  = lambda key, x: hashlib.blake2s(x, key=key, digest_size=16).digest()
                HMAC = lambda key, x: hmac.digest(key, x, hashlib.blake2s)
                p, mac1, mac2 = struct.unpack('<116s16s16s', data)
                assert mac1 == MAC(HASH(b"mac1----" + self.public_key), p), "Wrong mac1, possibly wrong public key"
                assert mac2 == b'\x00'*16, "Wrong mac2"
                index = next(self.sender_index_generator)
                sender_index, unencrypted_ephemeral, encrypted_static, encrypted_timestamp = struct.unpack('<4xI32s48s28s', data[:-32])

                chaining_key = HASH(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
                hash0 = HASH(HASH(HASH(chaining_key + b"WireGuard v1 zx2c4 Jason@zx2c4.com") + self.public_key) + unencrypted_ephemeral)
                chaining_key = HMAC(HMAC(chaining_key, unencrypted_ephemeral), b"\x01")
                temp = HMAC(chaining_key, crypto.X25519(self.private_key, unencrypted_ephemeral))
                chaining_key = HMAC(temp, b"\x01")
                static_public = crypto.aead_chacha20poly1305_decrypt(HMAC(temp, chaining_key + b"\x02"), 0, encrypted_static, hash0)
                assert static_public in ACCEPTED_KEYS, f"Unexpected static public {base64.b64encode(static_public).decode()}, possibly wrong client"
                hash0 = HASH(hash0 + encrypted_static)
                temp = HMAC(chaining_key, crypto.X25519(self.private_key, static_public))
                chaining_key = HMAC(temp, b"\x01")
                timestamp = crypto.aead_chacha20poly1305_decrypt(HMAC(temp, chaining_key + b"\x02"), 0, encrypted_timestamp, hash0)
                hash0 = HASH(hash0 + encrypted_timestamp)

                ephemeral_private = os.urandom(32)
                ephemeral_public = crypto.X25519(ephemeral_private, 9)
                hash0 = HASH(hash0 + ephemeral_public)
                chaining_key = HMAC(HMAC(HMAC(HMAC(HMAC(HMAC(chaining_key, ephemeral_public), b"\x01"), crypto.X25519(ephemeral_private, unencrypted_ephemeral)), b"\x01"), crypto.X25519(ephemeral_private, static_public)), b"\x01")
                temp = HMAC(chaining_key, self.preshared_key)
                chaining_key = HMAC(temp, b"\x01")
                temp2 = HMAC(temp, chaining_key + b"\x02")
                key = HMAC(temp, temp2 + b"\x03")
                hash0 = HASH(hash0 + temp2)
                encrypted_nothing = crypto.aead_chacha20poly1305_encrypt(key, 0, b"", hash0)
                #hash0 = HASH(hash0 + encrypted_nothing)
                msg = struct.pack('<III32s16s', 2, index, sender_index, ephemeral_public, encrypted_nothing)
                msg = msg + MAC(HASH(b"mac1----" + static_public), msg) + b'\x00'*16
                self.transport.sendto(msg, addr)
                print('login', addr, sender_index)

                temp = HMAC(chaining_key, b"")
                receiving_key = HMAC(temp, b"\x01")
                sending_key = HMAC(temp, receiving_key + b"\x02")
                self.keys[index] = (sender_index, receiving_key, sending_key)
                self.index_generators[index] = itertools.count()
            elif cmd == 4 and len(data) >= 32:
                _, index, counter = struct.unpack('<IIQ', data[:16])
                sender_index, receiving_key, sending_key = self.keys[index]
                packet = crypto.aead_chacha20poly1305_decrypt(receiving_key, counter, data[16:], b'')
                def reply(data):
                    counter = next(self.index_generators[index])
                    data = data + b'\x00'*((-len(data))%16)
                    msg = crypto.aead_chacha20poly1305_encrypt(sending_key, counter, data, b'')
                    msg = struct.pack('<IIQ', 4, sender_index, counter) + msg
                    self.transport.sendto(msg, addr)
                    return True
                if packet:
                    self.ippacket.handle_ipv4(addr[:2], packet, reply)
                else:
                    reply(b'')
        except Exception as exc:
            print(addr, type(exc).__name__, str(exc))
            return

def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-wg', dest='wireguard', default=51820, type=int, help='start a wireguard vpn with port number (default: off)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=pproxy.Connection, help='tcp remote server uri (default: direct)')
    parser.add_argument('-ur', dest='urserver', default=[], action='append', type=pproxy.Connection, help='udp remote server uri (default: direct)')
    parser.add_argument('-s', dest='salgorithm', default='fa', choices=('fa', 'rr', 'rc', 'lc'), help='scheduling algorithm (default: first_available)')
    parser.add_argument('-dns', dest='dns', default='1.1.1.1', help='dns server (default: 1.1.1.1)')
    parser.add_argument('-nc', dest='nocache', default=None, action='store_true', help='do not cache dns (default: off)')
    parser.add_argument('-v', dest='v', action='count', help='print verbose output')
    args = parser.parse_args()
    args.DIRECT = pproxy.DIRECT
    loop = asyncio.get_event_loop()

    transport3, _ = loop.run_until_complete(loop.create_datagram_endpoint(lambda: WIREGUARD(args), ('0.0.0.0', args.wireguard)))
    print(f'Serving Wireguard on udp/{args.wireguard}...')

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('Exiting by Ctrl-C...')

    for task in asyncio.all_tasks(loop):
        task.cancel()
    transport3.close()
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()

if __name__ == '__main__':
    main()
