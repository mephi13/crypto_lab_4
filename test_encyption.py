import pytest
import os
from enctool import Encryptor, enc_text, logger
from dotenv import load_dotenv
from Crypto import Random


messages = [
    "message 1",
    "asd /23 M!#@K:#M!@ L:KM!@#!2 ",
    "asd qw e\n adqw \n adsq w/1@ \\",
    "hello",
    "adf L! ",
    "other",
    "working",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
]

load_dotenv()
password = os.environ["KEYSTORE_PASSWORD"]
keystore = ".keystore"
key_id = "key"

def _test_strings(mode):
    #test string encryption/decryption
    encryptor = Encryptor(password, mode, key_id)
    for message in messages:
        ctext = encryptor.encrypt(message)
        assert isinstance(ctext, enc_text) 
        assert isinstance(ctext.ctext, bytes)

        plaintext = encryptor.decrypt(ctext)
        assert plaintext == message

    # wrong key test
    encryptor_key2 = Encryptor(password, mode, "key2")
    ctext = encryptor.encrypt(messages[0])
    assert isinstance(ctext, enc_text) 
    assert isinstance(ctext.ctext, bytes)

    plaintext = encryptor_key2.decrypt(ctext)
    assert not plaintext

    # random key test
    for i in range(8):
        key = Random.get_random_bytes(128//8)
        encryptor = Encryptor(password, mode, key_id)
        for message in messages:
            ctext = encryptor.encrypt(message, custom_key=key)
            assert isinstance(ctext, enc_text) 
            assert isinstance(ctext.ctext, bytes)

            plaintext = encryptor.decrypt(ctext, custom_key=key)
            assert plaintext == message

        # wrong key decryption test
        ctext = encryptor.encrypt(messages[0], custom_key=key)
        assert isinstance(ctext, enc_text) 
        assert isinstance(ctext.ctext, bytes)
        # without custom key, using key from keystore
        plaintext = encryptor.decrypt(ctext)
        assert not plaintext

def _clear_files():
    with open("test_file.txt", "w") as f:
        f.write("")  
    with open("test_file.dec", "w") as f:
        f.write("")  
    with open("test_file.enc", "w") as f:
        f.write("")  

def _test_files(mode):
    _clear_files()

    encryptor = Encryptor(password, mode, key_id)
    for message in messages:
        with open("test_file.txt", "w") as f:
            f.write(message)  

        ctext = encryptor.encrypt("test_file.txt", file=True, save_as="test_file.enc")
        assert isinstance(ctext, enc_text) 
        assert isinstance(ctext.ctext, bytes)

        encryptor.decrypt("test_file.enc", file=True, save_as="test_file.dec")
        
        with open("test_file.dec") as f:
            plaintext = f.read()

        assert plaintext == message

    _clear_files()

    # random key test
    for i in range(8):
        key = Random.get_random_bytes(128//8)
        encryptor = Encryptor(password, mode, key_id)
        for message in messages:
            with open("test_file.txt", "w") as f:
                f.write(message)  

            ctext = encryptor.encrypt("test_file.txt", file=True, save_as="test_file.enc", custom_key=key)
            assert isinstance(ctext, enc_text) 
            assert isinstance(ctext.ctext, bytes)

            encryptor.decrypt("test_file.enc", file=True, save_as="test_file.dec", custom_key=key)
            
            with open("test_file.dec") as f:
                plaintext = f.read()

            assert plaintext == message

        _clear_files()

        # wrong key decryption test
        with open("test_file.txt", "w") as f:
            f.write(messages[0])  

        encryptor.encrypt("test_file.txt", file=True, save_as="test_file.enc", custom_key=key)
        # without custom key, using key from keystore
        encryptor.decrypt("test_file.enc", file=True, save_as="test_file.dec")

        with open("test_file.dec") as f:
            plaintext = f.read()

        assert not plaintext or plaintext != messages[0]

        # and with custom key, just to make sure
        encryptor.encrypt("test_file.txt", file=True, save_as="test_file.enc")
        encryptor.decrypt("test_file.enc", file=True, save_as="test_file.dec")

        with open("test_file.dec") as f:
            plaintext = f.read()
        assert plaintext == messages[0]

def test_encryption_string_cbc():
    _test_strings("CBC")
    
def test_file_encryption_cbc():
    _test_files("CBC")

def test_encryption_string_gcm():
    _test_strings("GCM")
    
def test_file_encryption_gcm():
    _test_files("GCM")

def test_encryption_string_icbc():
    _test_strings("ICBC")

def test_file_encryption_icbc():
    _test_files("ICBC")