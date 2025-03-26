#!/usr/bin/env python3
"""
ICMP Covert Channel Server
Receives and decrypts data from custom ICMP type 47 packets
"""


import socket
import struct
import sys
import collections
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
import argparse
import getpass

# ICMP Type 47 (Reserved)
ICMP_TYPE = 47
ICMP_CODE = 0
BUFFER_SIZE = 65536

#AES key and HMAC key from password
def derive_key(password, salt):
    backend = default_backend()
    
    #PBKDF2 to derive keys
    kdf = hashes.Hash(hashes.SHA256(), backend=backend)
    kdf.update(password.encode() + salt)
    derived_key = kdf.finalize()
    
    # Split key into encryption key and HMAC key
    # 256-bit AES key
    encryption_key = derived_key[:32]  
    # 256-bit HMAC key
    hmac_key = derived_key[32:64]      
    
    return encryption_key, hmac_key

#Decrypting with AES-256-CBC 
def decrypt_data(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpading
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext

#Verify HMAC for data authentication
def verify_hmac(data, hmac_value, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(hmac_value)
        return True
    except Exception:
        return False

#Verify the checksum for ICMP header
def verify_checksum(data):
    checksum = 0
    count_to = (len(data) // 2) * 2

    for count in range(0, count_to, 2):
        this_val = data[count] + (data[count + 1] << 8)
        checksum += this_val
        checksum &= 0xffffffff

    if count_to < len(data):
        checksum += data[len(data) - 1]
        checksum &= 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    answer = ~checksum
    answer &= 0xffff
    return answer == 0

def process_icmp_packet(data, encryption_key, hmac_key):
    # ICMP header
    icmp_header = data[:8]
    
    # ICMP type and code
    icmp_type, icmp_code = struct.unpack('!BB', icmp_header[:2])
    
    # Checking our custom ICMP type
    if icmp_type != ICMP_TYPE or icmp_code != ICMP_CODE:
        return None
    
    # Verifing checksum
    if not verify_checksum(data):
        print("Checksum verification failed, packet might be tampered")
        return None
    
    #Payload after ICMP header
    payload = data[8:]
    
    # Extracting HMAC
    hmac_value = payload[:32]
    message = payload[32:]
    
    # HMAC verification 
    if not verify_hmac(message, hmac_value, hmac_key):
        print("HMAC verification failed, packet might be tampered")
        return None
    
    # Extracting IV 
    iv = message[:16]
    encrypted_data = message[16:]
    
    # Decrypting
    try:
        decrypted_data = decrypt_data(encrypted_data, encryption_key, iv)
        return decrypted_data
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='ICMP Covert Channel Server')
    parser.add_argument('-i', '--interface', default='', help='Interface to listen on')
    parser.add_argument('-s', '--salt', default='customsalt', help='Salt for key derivation')
    args = parser.parse_args()
    
    # Geting passphrase
    password = getpass.getpass("Enter the secret passphrase: ")
    
    #Encryption and HMAC keys
    encryption_key, hmac_key = derive_key(password, args.salt.encode())
    
    #Buffer to handle
    message_buffer = collections.defaultdict(bytearray)

    try:
        # Raw socket for ICMP 
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Bind to interface
        if args.interface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode())
        
        print("ICMP Covert Channel Server - Listening for type 47 ICMP packets...")
        
        while True:
            packet_data, addr = sock.recvfrom(BUFFER_SIZE)
            
            # IP header is usually 20 bytes, extract ICMP portion
            ip_header_length = (packet_data[0] & 0x0F) * 4
            icmp_packet = packet_data[ip_header_length:]
            
            decrypted_chunk = process_icmp_packet(icmp_packet, encryption_key, hmac_key)
            
            if decrypted_chunk:
                # Extract source IP and sequence number for message identification
                source_ip = addr[0]
                seq = struct.unpack('!H', icmp_packet[6:8])[0]
                
                # First 4 bytes are the length prefix
                if len(message_buffer[source_ip]) == 0:
                    total_length = struct.unpack('!I', decrypted_chunk[:4])[0]
                    message_buffer[source_ip].extend(decrypted_chunk[4:])
                else:
                    message_buffer[source_ip].extend(decrypted_chunk)
                
                # Check if we have the complete message
                if 'total_length' in locals() and len(message_buffer[source_ip]) >= total_length:
                    try:
                        message = message_buffer[source_ip][:total_length].decode()
                        print(f"\nMessage from {source_ip}: {message}")
                        
                        # Clear the buffer for this source
                        message_buffer[source_ip] = bytearray()
                    except UnicodeDecodeError:
                        print(f"\n[ERROR] Failed to decode message from {source_ip}")
                        message_buffer[source_ip] = bytearray()
            
    except PermissionError:
        print("Raw socket creation requires root privileges")
        print("Please run the script with sudo or as administrator")
        sys.exit(1)
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    main()

