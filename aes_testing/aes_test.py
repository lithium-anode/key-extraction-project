from pyshark import FileCapture
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from Crypto.Util import Counter
import string

pcap_path = '/path/to/pcap/file.pcap'
log_path = '/path/to/log/file.log'
f = open(log_path, 'w', encoding='utf-8', errors='replace')
printable_chars = string.printable.encode()
s2c_key = unhexlify('key')
s2c_iv = unhexlify('iv')
c2s_key = unhexlify('key')
c2s_iv = unhexlify('iv')
s2c_ctr = Counter.new(128, initial_value=int.from_bytes(s2c_iv, byteorder='big'))
s2c_cipher = AES.new(s2c_key, AES.MODE_CTR, counter=s2c_ctr)
c2s_ctr = Counter.new(128, initial_value=int.from_bytes(c2s_iv, byteorder='big'))
c2s_cipher = AES.new(c2s_key, AES.MODE_CTR, counter=c2s_ctr)

def extract_ssh_payloads_json(pcap_path):
    cap = FileCapture(pcap_path, display_filter='ssh', use_json=True, include_raw=True)

    for packet in cap:
        print(f"--- Frame {packet.number} ---", file=f)
        ssh_fields = packet.ssh._all_fields
        direction = "S2C" if ssh_fields.get('ssh.direction') == "1" else "C2S"

        for key, value in ssh_fields.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        process_entry(item, direction)
            elif isinstance(value, dict):
                process_entry(value, direction)

        print("\n", file=f)

def process_entry(data, direction):
    if 'ssh.encrypted_packet_raw' not in data: return
    # `full_payload` contains the actual encrypted data of the entire frame
    packet_len = data.get('ssh.packet_length_raw', 'Unknown')[0]
    raw_payload = data.get('ssh.encrypted_packet_raw')[0]
    # print(f"packet_len: {packet_len}\t{len(packet_len)}\nraw_payload: {raw_payload}\t{len(raw_payload)}", file=f)
    full_payload = unhexlify(packet_len + raw_payload)
    # print(f"full_payload: {full_payload}", file=f)
    payload_len = len(full_payload)
    # print(f"payload_len: {payload_len}", file=f)
    cipher = s2c_cipher if direction == "S2C" else c2s_cipher
    idx = 0

    while idx < payload_len:
        # print(f"1st 4 bytes: {hexlify(full_payload[idx:idx+4])}", file=f)
        current_packet_len = int.from_bytes(full_payload[idx:idx+4], byteorder='big')

        payload_start = idx + 4
        payload_end = payload_start + current_packet_len
        # print(f"current_packet_len: {current_packet_len}\npayload_start: {payload_start}\npayload_end: {payload_end}", file=f)
        ciphertext = full_payload[payload_start:payload_end]
        
        plaintext = cipher.decrypt(ciphertext)

        readable = bytes(b if b in printable_chars else ord('.') for b in plaintext).decode('ascii', errors='replace')
        print(f"[{direction}] Sub-Packet: Len={current_packet_len}", file=f)
        print(f"    Decrypted: {readable}", file=f)

        idx = payload_end + 8

extract_ssh_payloads_json(pcap_path)

f.close()

