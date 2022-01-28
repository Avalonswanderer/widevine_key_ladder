#! /usr/bin/python

import argparse
import Crypto.Cipher.PKCS1_OAEP as rsaoaep
import Crypto.Util as crypto_util
from Crypto.Util.Padding import unpad
import Crypto.PublicKey.RSA as RSA
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def read_bin_file(filename):
    return open(filename, 'rb').read()

def gen_128_cmac(key, context, header):
    cmac_obj = CMAC.new(key, ciphermod=AES)
    cmac_obj.update(header + context)
    return cmac_obj.digest()

def gen_asset_key(key, encryption_context):
    return gen_128_cmac(key, encryption_context, b'\x01')

def gen_mac_client_key(key, mac_context):
    first = gen_128_cmac(key, mac_context, b'\x01')
    second = gen_128_cmac(key, mac_context, b'\x02')
    return b"".join([first, second])

def gen_mac_server_key(key, mac_context):
    first = gen_128_cmac(key, mac_context, b'\x03')
    second = gen_128_cmac(key, mac_context, b'\x04')
    return b"".join([first, second])
    
def get_cert_from_asset_key(asset_key, enc_device_rsa_key, device_rsa_key_iv):
    decipher = AES.new(asset_key, AES.MODE_CBC, device_rsa_key_iv)
    device_rsa_key_w_pad = decipher.decrypt(enc_device_rsa_key)
    return unpad(device_rsa_key_w_pad, AES.block_size)

def get_clear_session_key(device_rsa_key, enc_session_key):
    rsa_oaep_cipher = rsaoaep.new(device_rsa_key)
    return rsa_oaep_cipher.decrypt(enc_session_key)

def get_clear_content_key(asset_key, loadkey_buffer, offset):
    iv = loadkey_buffer[offset + 0x12:offset + 0x22]
    enc_content_key = loadkey_buffer[offset + 0x24:offset + 0x44]
    decipher = AES.new(asset_key, AES.MODE_CBC, iv)
    content_key_w_pad = decipher.decrypt(enc_content_key)
    return unpad(content_key_w_pad, AES.block_size)

def get_clear_kctl_block(content_key, loadkey_buffer, offset):
    enc_kctl = loadkey_buffer[offset + 0x52:offset + 0x72]
    iv_kctl = loadkey_buffer[offset + 0x74:offset + 0x84]
    decipher = AES.new(content_key, AES.MODE_CBC, iv_kctl)
    kctl_pad = decipher.decrypt(enc_kctl)
    return unpad(kctl_pad, AES.block_size)

def get_content_keys(asset_key, loadkeys_buffer, num_content_keys):
    offset_loadkeys = loadkeys_buffer.find(b'\x20\x01\x1a\x86\x01\x0a\x10') + 7
    for i in range(0, num_content_keys):
        offset = offset_loadkeys + i * 0x89
        content_key = get_clear_content_key(asset_key, loadkeys_buffer, offset)
        print("content key ID: " + loadkeys_buffer[offset:offset + 0x10].hex())
        print("content key: " + content_key.hex())
        kctl = get_clear_kctl_block(content_key, loadkeys_buffer, offset)
        print("kctl: " + kctl.hex())

def get_server_key(asset_key, loadkeys_buffer):
    offset_server_key = loadkeys_buffer.find(b'\x1a\x50') + 2
    enc_server_key = loadkeys_buffer[offset_server_key:offset_server_key + 0x50]
    iv = loadkeys_buffer[offset_server_key - 0x12:offset_server_key - 2]
    decipher = AES.new(asset_key, AES.MODE_CBC, iv)
    server_key_pad = decipher.decrypt(enc_server_key)
    return unpad(server_key_pad, AES.block_size)

def gen_mac_keys(key, context):
    mac_client_key = gen_mac_client_key(key, context)
    mac_server_key = gen_mac_server_key(key, context)
    return mac_client_key, mac_server_key
    

def parser_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device_key", help="clear device key in hex from the Keybox.")
    parser.add_argument("--encryption_context", help="file with the encryption context from GenerateDerivedKeys.")
    parser.add_argument("--mac_context", help="file with the mac context from GenerateDerivedKeys.")
    parser.add_argument("--enc_device_rsa_key", help="file with the encrypted Device RSA Key from RewrapDeviceRSAKey.")
    parser.add_argument("--device_rsa_key_iv", help="IV in hex for the encrypted Device RSA Key from RewrapDeviceRSAKey.")
    parser.add_argument("--cert", help="file with the clear certificate.")
    parser.add_argument("--enc_session_key", help="file with the encrypted session key.")
    parser.add_argument("--encryption_context_session", help="file with the encryption context from DeriveKeysFromSessionKey.")
    parser.add_argument("--mac_context_session", help="file with the mac context from DeriveKeysFromSessionKey")
    parser.add_argument("--loadkeys_buffer", help="file with the Loadkeys buffer containing the encrypted content keys.")
    parser.add_argument("-n", "--num_content_keys", type=int, help="number of content key in LoadKeys.")
    parser.add_argument("--server_key", help="set if there is a server key in LoadKeys.", action="store_true")    
    return parser.parse_args()


def main():
    args = parser_args()
    if (args.cert == None):
        encryption_context = read_bin_file(args.encryption_context)
        device_key = bytearray.fromhex(args.device_key)

        if (args.mac_context != None):
            mac_context = read_bin_file(args.mac_context)
            mac_client_key, mac_server_key = gen_mac_keys(device_key, mac_context)
            print("device key derived mac client key: " + mac_client_key.hex())
            print("device key derived mac server key: " + mac_server_key.hex())
            
        asset_key = gen_asset_key(device_key, encryption_context)
        print("device key derived asset key: " + asset_key.hex())
        enc_device_rsa_key = read_bin_file(args.enc_device_rsa_key)
        device_rsa_key_iv = bytearray.fromhex(args.device_rsa_key_iv)
        cert = get_cert_from_asset_key(asset_key, enc_device_rsa_key, device_rsa_key_iv)
    else:
        cert = read_bin_file(args.cert)
    device_rsa_key = RSA.importKey(cert)

    enc_session_key = read_bin_file(args.enc_session_key)
    session_key = get_clear_session_key(device_rsa_key, enc_session_key)
    print("session key: " + session_key.hex())

    if (args.mac_context_session != None):
        mac_context_session = read_bin_file(args.mac_context_session)
        mac_client_key, mac_server_key = gen_mac_keys(session_key, mac_context_session)
        print("session key derived mac client key: " + mac_client_key.hex())
        print("session key derived mac server key: " + mac_server_key.hex())
    
    encryption_context_session = read_bin_file(args.encryption_context_session)
    asset_key = gen_asset_key(session_key, encryption_context_session)
    print("session key derived asset key: " + asset_key.hex())

    loadkeys_buffer = read_bin_file(args.loadkeys_buffer)
    if (args.server_key == True):
        server_key = get_server_key(asset_key, loadkeys_buffer)
        print("server key: " + server_key[:0x20].hex()) # as truncated by Widevine CDM
    
    get_content_keys(asset_key, loadkeys_buffer, args.num_content_keys)
    
if __name__ == '__main__':
    main()
