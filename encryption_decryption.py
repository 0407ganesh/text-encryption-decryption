import string, base64, hashlib

class EncryptionDecryption:
    def __init__(self):
        self.alphabet = string.ascii_lowercase
    
    def caesar_encrypt(self, text, shift=3):
        result = ""
        for char in text.lower():
            if char in self.alphabet:
                shifted = (self.alphabet.index(char) + shift) % 26
                result += self.alphabet[shifted]
            else:
                result += char
        return result
    
    def caesar_decrypt(self, text, shift=3):
        return self.caesar_encrypt(text, -shift)
    
    def vigenere_encrypt(self, text, key):
        result = ""
        key = key.lower()
        key_index = 0
        for char in text.lower():
            if char in self.alphabet:
                shift = self.alphabet.index(key[key_index % len(key)])
                shifted = (self.alphabet.index(char) + shift) % 26
                result += self.alphabet[shifted]
                key_index += 1
            else:
                result += char
        return result
    
    def vigenere_decrypt(self, text, key):
        result = ""
        key = key.lower()
        key_index = 0
        for char in text.lower():
            if char in self.alphabet:
                shift = self.alphabet.index(key[key_index % len(key)])
                shifted = (self.alphabet.index(char) - shift) % 26
                result += self.alphabet[shifted]
                key_index += 1
            else:
                result += char
        return result
    
    def base64_encode(self, text):
        return base64.b64encode(text.encode()).decode()
    
    def base64_decode(self, encoded_text):
        return base64.b64decode(encoded_text).decode()
    
    def simple_xor_encrypt(self, text, key):
        result = ""
        for i, char in enumerate(text):
            key_char = key[i % len(key)]
            result += chr(ord(char) ^ ord(key_char))
        return base64.b64encode(result.encode()).decode()
    
    def simple_xor_decrypt(self, encoded_text, key):
        encrypted = base64.b64decode(encoded_text).decode()
        result = ""
        for i, char in enumerate(encrypted):
            key_char = key[i % len(key)]
            result += chr(ord(char) ^ ord(key_char))
        return result
    
    def hash_text(self, text, algorithm='sha256'):
        if algorithm == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        else:
            return None
