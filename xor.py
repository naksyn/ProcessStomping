import sys

def xor_encrypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as file:
        plaintext = file.read()
    ciphertext = xor_encrypt(plaintext, key.encode('utf-8'))
    
    with open(output_file_path, 'wb') as file:
        file.write(ciphertext)

if len(sys.argv) != 4:
    print("Usage: python encrypt.py <input file> <output file> <key string>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]
key_string = sys.argv[3]

# Encrypt the file
encrypt_file(input_file, output_file, key_string)

print(f"File '{input_file}' has been encrypted and saved to '{output_file}' using the key '{key_string}'.")