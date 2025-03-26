#!/usr/bin/env python3
"""
ICMP Covert Channel Client
Sends encrypted data using custom ICMP type 47 packets
"""

import sys
import socket
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import argparse
import getpass



# ICMP Type 47 (Reserved)
ICMP_TYPE = 47
ICMP_CODE = 0
BUFFER_SIZE = 1024
# Max payload size avoiding fragmentation. 
MAX_PAYLOAD_SIZE = 1400

#Calculating checksum for ICMP header 
def calculate_checksum(data):
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
    return answer
#Derive AES key and HMAC key from password
def derive_key(password, salt):
    backend = default_backend()
    
    #PBKDF2 to derive keys
    kdf = hashes.Hash(hashes.SHA256(), backend=backend)
    kdf.update(password.encode() + salt)
    derived_key = kdf.finalize()
    
    # Spliting the derived key into encryption key and HMAC key
    # 256-bit AES key
    encryption_key = derived_key[:32]  
    # 256-bit HMAC key
    hmac_key = derived_key[32:64]      
    return encryption_key, hmac_key

#Encrypting data with AES-256-CBC with padding
def encrypt_data(plaintext, key, iv):
    # Pad plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypting with AES-256-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext

#Creating HMAC for data authentication
def create_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

#Create and send an ICMP packet with encrypted data
def send_icmp_packet(sock, dest_ip, sequence, data, encryption_key, hmac_key):
    # Generating random IV for each packet
    iv = os.urandom(16)
    
    # Encrypting
    encrypted_data = encrypt_data(data, encryption_key, iv)
    
    # Creating message with IV and encrypted data
    message = iv + encrypted_data
    
    # Creating HMAC for authentication
    message_hmac = create_hmac(message, hmac_key)
    
    # Combining HMAC with message
    final_payload = message_hmac + message
    
    #ICMP header creating (8 bytes: type, code, checksum, id, sequence)
    icmp_header = struct.pack('!BBHHH', ICMP_TYPE, ICMP_CODE, 0, os.getpid() & 0xFFFF, sequence)
    
    # Calculate and add checksum
    checksum = calculate_checksum(icmp_header + final_payload)
    icmp_header = struct.pack('!BBHHH', ICMP_TYPE, ICMP_CODE, socket.htons(checksum), os.getpid() & 0xFFFF, sequence)
    
    #Final packet creation
    packet = icmp_header + final_payload
    
    # Sending the packet
    sock.sendto(packet, (dest_ip, 0))
    return len(data)

#Split data into chunks
def chunk_data(data, chunk_size):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

def main():
    parser = argparse.ArgumentParser(description='ICMP Covert Channel Client')
    parser.add_argument('destination', help='Destination IP address')
    parser.add_argument('-p', '--port', type=int, default=0, help='Optional port (ignored for ICMP but needed for some firewalls)')
    parser.add_argument('-s', '--salt', default='customsalt', help='Salt for key derivation')
    args = parser.parse_args()
    
    #Passphrase
    password = getpass.getpass("Enter the secret passphrase: ")
    
    # Encryption and HMAC keys
    encryption_key, hmac_key = derive_key(password, args.salt.encode())
    
    try:
        # Create raw socket for ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
        
        sequence = 1
        
        print(f"ICMP Covert Channel Client - Target: {args.destination}")
        print("Type messages to send (Ctrl+C to exit):")
        
        while True:
            try:
                # Get message from user
                message = input("> ")
                if not message:
                    continue
                
                # Encode the message
                data = message.encode()
                
                #length prefix to data
                data_with_length = struct.pack('!I', len(data)) + data
                
                # Split data into chunks to avoid fragmentation
                chunks = chunk_data(data_with_length, MAX_PAYLOAD_SIZE - 16 - 32)  # Account for IV and HMAC
                
                total_sent = 0
                for i, chunk in enumerate(chunks):
                    # Send each chunk as a separate ICMP packet
                    chunk_sent = send_icmp_packet(sock, args.destination, sequence + i, chunk, encryption_key, hmac_key)
                    total_sent += chunk_sent
                    time.sleep(0.01)  #Delay between packets
                
                sequence += len(chunks)
                print(f"Sent {total_sent} bytes in {len(chunks)} packet(s)")
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            
    except PermissionError:
        print("Error: Raw socket creation requires root privileges")
        print("Please run the script with sudo or as administrator")
        sys.exit(1)
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    main()
