# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import argparse, pathlib, sys, pickle
import msvcrt
import colorama
from colorama import Fore, Style


def adjust_key(key):
    salt = b'salt_unico'  # Sal única para cada clave
    iterations = 5000  # Número de iteraciones para el algoritmo PBKDF2

    # Derivar la clave utilizando PBKDF2 con SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    adjusted_key = kdf.derive(key.encode())

    return adjusted_key


def encrypt_data(plaintext, key):
    # Ajustar la clave al tamaño correcto
    key = adjust_key(key)

    # Generar un vector de inicialización (IV) único y aleatorio
    iv = os.urandom(16)

    # Crear un objeto Cipher con AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Pad el texto plano para que sea un múltiplo del tamaño del bloque de cifrado
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Cifrar los datos
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Concatenar IV y texto cifrado y codificar en base64
    encrypted_data = base64.b64encode(iv + ciphertext)

    return encrypted_data


def decrypt_data(encrypted_data, key):
    # Ajustar la clave al tamaño correcto
    key = adjust_key(key)

    # Decodificar datos cifrados en base64
    encrypted_data = base64.b64decode(encrypted_data)

    # Extraer IV y texto cifrado
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Crear un objeto Cipher con AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Descifrar los datos
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Despad el texto plano
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def crypt_decrypt_file(file, key, action):
    
    if action == 'encrypt':
        new_file = file.with_name(file.name+'.nox')
    elif action == 'decrypt':
        new_file = file.with_name(file.stem)
    
    with open(file.absolute(), 'rb') as f:
        data = f.read()

    if action == 'encrypt':
        try:
            data = encrypt_data(data, key)
        
        except (KeyboardInterrupt):
            print(f'\n{Fore.LIGHTRED_EX}[END]{Style.RESET_ALL}: Operación cancelada por el usuario.')
            sys.exit(0)
        
        except (Exception) as err:
            return err
    
    elif action == 'decrypt':
        try:
            data = decrypt_data(data, key)
        
        except (KeyboardInterrupt):
            print(f'\n{Fore.LIGHTRED_EX}[END]{Style.RESET_ALL}: Operación cancelada por el usuario.')
            sys.exit(0)
            
        except (Exception) as err:
            return err
    
    try:
        with open(new_file.absolute(), 'wb') as f:
            f.write(data)
    
    except (KeyboardInterrupt):
        print(f'\n{Fore.LIGHTRED_EX}[END]{Style.RESET_ALL}: Operación cancelada por el usuario.')
        if new_file.exists():
            new_file.unlink()
        sys.exit(0)
    
    except (Exception) as err:
        return err
    

def get_passwd():
    prompt="Introduce la clave secreta: "
    passwd = ''
    interrupted = False
    
    sys.stdout.write(prompt)
    sys.stdout.flush()        
    
    while True:
        char = msvcrt.getch()
    
        if char == b'\r' or char == b'\n':
            sys.stdout.write('\n')
            break
    
        if char == b'\x08':  # Tecla de retroceso
            if len(passwd) > 0:
                passwd = passwd[:-1]
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        elif char == b'\x03':
            interrupted = True
            break            
        
        else:
            passwd += char.decode("utf-8")
            sys.stdout.write(f'{Fore.GREEN}*{Style.RESET_ALL}')
            sys.stdout.flush()
    
    print()
    if interrupted:
        print(f'\n{Fore.LIGHTRED_EX}[END]{Style.RESET_ALL}: Operación cancelada por el usuario.')
        sys.exit(0)
    
    return passwd


if __name__ == '__main__':
    colorama.init()
    # Crear el objeto ArgumentParser
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-k', '--key', help='Master key for encrypt/decrypt')
    parser.add_argument('path', help='Path to file or folder')
    parser.add_argument('-r', '--recursive', action='store_true', help='Encrypts/decrypts recursively in a path')
    parser.add_argument('-x', '--remove', action='store_true', help='Remove file after encrypt/decrypt')
    parser.add_argument('-v', '--verbose', action='store_true', help='Active error descriptions')
    
    # Crear un grupo de argumentos mutuamente excluyentes
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('-e', '--encrypt', action='store_true', help='Encrypt file')
    action.add_argument('-d', '--decrypt', action='store_true', help='Decrypt file')
    
    
    # Analizar los argumentos de la línea de comandos
    args = parser.parse_args()

    if not args.key:
        print(f"{Fore.LIGHTYELLOW_EX}[ATENTION]{Style.RESET_ALL} Si pierde la clave de cifrado no podrá recurar su archivo.")
        while True:
            args.key = get_passwd()
            if len(args.key) < 8:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} La clave debe tener mínimo 8 dígitos.")
            else:
                break
    
    ruta = pathlib.Path(args.path)
    
    if not ruta.exists():
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL}: El fichero o carpeta no existe o no es accesible.')
        sys.exit(0)

    if args.encrypt:
        if ruta.is_file():
            if ruta.suffix[1:].lower() == 'nox':
                print(f'{Fore.LIGHTYELLOW_EX}[WARNING]{Style.RESET_ALL}: {ruta.name} -> El fichero ya está encriptado.')
                sys.exit(0)

            code = crypt_decrypt_file(file=ruta, key=args.key, action='encrypt')
            if not code:
                print(f'{Fore.GREEN}[OK]{Style.RESET_ALL}: {ruta.name}')
                # intenta eliminar el archivo antiguo
                if args.remove:
                    try:
                        ruta.unlink()
                    except:
                        pass
            
            else:
                print(f'{Fore.RED}[ERROR]{Style.RESET_ALL}: {ruta.name}')
                if args.verbose:
                    print(code)
            
        
        elif ruta.is_dir():
            if args.recursive:
                files = ruta.rglob('*')
            else:
                files = ruta.glob('*')
            
            
            files = [x for x in files if x.is_file() and x.suffix[1:] != 'nox']
            print(f"Ficheros descifrados: {len(files)}")
            err = 0
            
            for file in files:
                # intenta cifrar el archivo
                code = crypt_decrypt_file(file=file, key=args.key, action='encrypt')
                if not code:
                    print(f'{Fore.GREEN}[OK]{Style.RESET_ALL}: {file.name}')
                    # intenta eliminar el archivo antiguo
                    if args.remove:
                        try:
                            file.unlink()
                        except:
                            pass                    
                else:
                    print(f'{Fore.RED}[ERROR]{Style.RESET_ALL}: {file.name}')
                    if args.verbose:
                        print(code)                    
                    err += 1
            
            print()
            if not err:
                print(f'{Fore.LIGHTGREEN_EX}[END]{Style.RESET_ALL}: Total cifrados {len(files)}')
            else:
                print(f'{Fore.MAGENTA}[END]{Style.RESET_ALL}: Cifrados: {len(files-err)} / Errores: {err}')
  
    
    elif args.decrypt:
        if ruta.is_file():
            if not ruta.suffix[1:].lower() == 'nox':
                print(f'{Fore.LIGHTYELLOW_EX}[WARNING]{Style.RESET_ALL}: {ruta.name} -> El fichero no está encriptado.')
                sys.exit(0)

            code = crypt_decrypt_file(file=ruta, key=args.key, action='decrypt')
            
            if not code:
                print(f'{Fore.GREEN}[OK]{Style.RESET_ALL}: {ruta.name}')
                if args.remove:
                    ruta.unlink()                
            else:
                print(f'{Fore.RED}[ERROR]{Style.RESET_ALL}: {ruta.name}')
                if args.verbose:
                    print(code)                
        
        elif ruta.is_dir():
            if args.recursive:
                files = ruta.rglob('*')
            else:
                files = ruta.glob('*')
            
            
            files = [x for x in files if x.is_file() and x.suffix[1:] == 'nox']
            print(f"Ficheros cifrados: {len(files)}")
            err = 0
        
            for file in files:
                code = crypt_decrypt_file(file=file, key=args.key, action='decrypt')
                if not code:
                    print(f'{Fore.GREEN}[OK]{Style.RESET_ALL}: {file.name}')
                    if args.remove:
                        try:
                            file.unlink()
                        except:
                            pass                    
                else:
                    print(f'{Fore.RED}[ERROR]{Style.RESET_ALL}: {file.name}')
                    if args.verbose:
                        print(code)                    
                    err += 1
            
            print()
            if not err:
                print(f'{Fore.LIGHTGREEN_EX}[END]{Style.RESET_ALL}: Total descifrados {len(files)}')
            else:
                print(f'{Fore.LIGHTRED_EX}[END]{Style.RESET_ALL}: Descifrados: {len(files)-err} / Errores: {err}')