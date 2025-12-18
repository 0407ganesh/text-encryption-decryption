#!/usr/bin/env python3

from encryption_decryption import EncryptionDecryption

def print_banner():
    print("\n" + "="*50)
    print("TEXT ENCRYPTION & DECRYPTION TOOL")
    print("Caesar | Vigenere | Base64 | XOR | Hashing")
    print("="*50 + "\n")

def interactive_mode():
    print_banner()
    cipher = EncryptionDecryption()
    
    while True:
        print("\n1. Caesar Cipher")
        print("2. Vigenere Cipher")
        print("3. Base64 Encode/Decode")
        print("4. XOR Cipher")
        print("5. Hash Text")
        print("6. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            text = input("Enter text: ")
            shift = int(input("Enter shift (default 3): ") or "3")
            print(f"Encrypted: {cipher.caesar_encrypt(text, shift)}")
            
        elif choice == '2':
            mode = input("Encrypt/Decrypt? (E/D): ").upper()
            text = input("Enter text: ")
            key = input("Enter key: ")
            if mode == 'E':
                print(f"Encrypted: {cipher.vigenere_encrypt(text, key)}")
            else:
                print(f"Decrypted: {cipher.vigenere_decrypt(text, key)}")
        
        elif choice == '3':
            mode = input("Encode/Decode? (E/D): ").upper()
            text = input("Enter text: ")
            if mode == 'E':
                print(f"Encoded: {cipher.base64_encode(text)}")
            else:
                print(f"Decoded: {cipher.base64_decode(text)}")
        
        elif choice == '4':
            mode = input("Encrypt/Decrypt? (E/D): ").upper()
            text = input("Enter text: ")
            key = input("Enter key: ")
            if mode == 'E':
                print(f"Encrypted: {cipher.simple_xor_encrypt(text, key)}")
            else:
                print(f"Decrypted: {cipher.simple_xor_decrypt(text, key)}")
        
        elif choice == '5':
            text = input("Enter text: ")
            algo = input("Algorithm (md5/sha1/sha256/sha512): ") or "sha256"
            print(f"Hash: {cipher.hash_text(text, algo)}")
        
        elif choice == '6':
            print("\nThank you!")
            break
        else:
            print("Invalid option!")

if __name__ == "__main__":
    interactive_mode()
