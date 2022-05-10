#!/usr/bin/env python
import argparse
import sys
import os
import jks
import pickle

from logging import Logger, StreamHandler, INFO, FileHandler, Formatter
from dotenv import load_dotenv
from dataclasses import dataclass
from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple


enc_text = namedtuple("enc_text", "ctext tag nonce_or_iv")
logger = Logger("encryptor_logger")
handler_file = FileHandler('file.log')
handler_file.setLevel(0)
f_format = Formatter('[%(asctime)s][%(name)s][%(levelname)s]: %(message)s')
handler_file.setFormatter(f_format)
logger.addHandler(handler_file)


class Encryptor:
    """Encryptor class capable of ecrypting and decrypting files."""
    password: str # keystore password
    mode: str # mode of encryption
    key_id: str # key identifier

    def __init__(self, password, mode ,key_id, keystore_path = ".keystore"):
        self.keystore_password = password
        self.keystore = keystore_path
        self.mode = mode
        self.key_id = key_id
        self._get_private_key()
        pass

    def _setup_AES(self, key=None):
        if not key:
            key = self.private_key
        else:
            logger.debug(f"Using custom key: {key}")
        mode = getattr(AES, "MODE_" + self.mode)
        logger.debug("AES mode: " + str(mode) + ", MODE_" + self.mode) 
        self.AES = AES.new(key, mode)

    def _get_private_key(self):
        try:
            keystore = jks.KeyStore.load(self.keystore, self.keystore_password)
        except:
            raise Exception(f"keystore {self.keystore} doesnt exist.")
        try:
            pk_entry = keystore.secret_keys[self.key_id]
            logger.debug("Keystore: " + str(keystore.secret_keys))
        except:
            raise Exception(f"Key with identifier {self.key_id} doesnt exist.")

        logger.debug("Key from keystore: " + str(pk_entry.key))
        # if the key could not be decrypted using the store password,
        # raise exception
        if not pk_entry.is_decrypted():
            raise Exception("Wrong keystore passphrase")

        self.private_key = pk_entry.key

    def encrypt(self, message, file=False, save_as=None, custom_key=None):
        # if were encrypting a file, read file
        self._setup_AES(key=custom_key)

        if save_as:
            with open(save_as, "w") as f:
                f.write("")

        if file:
            try:
                with open(message) as f:
                    message = f.read()
            except FileNotFoundError as ex:
                logger.error(f"No such file or directory: {message}")
                return

        logger.debug("Encrypting message: \n" + message)
        # encode end pad message
        message = message.encode("utf-16")
        message = pad(message, AES.block_size)

        # Mode is GCM
        if self.mode == "GCM":
            result = self.AES.encrypt_and_digest(message)
            ciphertext, tag = result
            nonce = self.AES.nonce
        # Mode is probably cBC
        elif self.mode == "CBC":
            result = self.AES.encrypt(message)
            ciphertext = result
            tag = None
            nonce = self.AES.iv

        result = enc_text(ciphertext, tag, nonce)
        logger.debug("Encryption result: ")
        logger.debug(result)

        # save to file
        if save_as:
            logger.debug(f"Saving enrypted file as {save_as}")
            with open(save_as, "wb") as f:
                pickle.dump(result, f)

        return result

    def decrypt(self, ctext, file = False, save_as=None, custom_key=None):
        key = custom_key if custom_key else self.private_key

        if save_as:
            with open(save_as, "w") as f:
                f.write("")

        if file:
            logger.debug(f"Loading file {ctext} for decryption")
            try:
                pickle_off = open(ctext, "rb")
                ctext = pickle.load(pickle_off)
                logger.debug(f"Unpickled file as: {ctext}")
            except FileNotFoundError as ex:
                logger.error(f"No such file or directory: {ctext}")
                return
            except pickle.UnpicklingError as ex:
                logger.error(f"Cannot unpickle file {ctext}. Are you sure this is the encrypted file?")
                return

        logger.debug("Decrypting ciphertext: ")
        logger.debug(ctext)

        if self.mode == "CBC":
            iv = ctext.nonce_or_iv
            ciphertext = ctext.ctext
            decryptor = AES.new(key, AES.MODE_CBC, iv=iv)
            try: 
                plaintext = (decryptor.decrypt(ciphertext))
                plaintext = unpad(plaintext, AES.block_size)
            except ValueError as ex:
                logger.error(ex)
                return None

        if self.mode == "GCM":
            nonce = ctext.nonce_or_iv
            ciphertext = ctext.ctext
            tag = ctext.tag
            decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try: 
                plaintext = decryptor.decrypt_and_verify(ciphertext=ciphertext,received_mac_tag=tag)
                plaintext = unpad(plaintext, AES.block_size)
            except ValueError as ex:
                logger.error(ex)
                return None

        plaintext = plaintext.decode("utf-16")
        logger.debug(f"Decrypted message: \n{plaintext}")

        if save_as:
            with open(save_as, "w") as f:
                f.write(plaintext)


        return plaintext


if __name__=="__main__":
    try:
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-d", "--decrypt", type=str, nargs=2, help="decrypt file(s) on disk")
        group.add_argument("-e", "--encrypt", type=str, nargs=2, help="encrypt file(s) on disk")
        group.add_argument("-c", "--challenge", type=str, nargs=2, help="challenge mode - on input [m0, m1] pick independently, \
    uniformly at random a bit b and return a ciphertext cb of a message mb")
        group.add_argument("-o", "--oracle", type=str, nargs='?', help="oracle mode - on input consisting of q messages, return q ciphertexts")

        parser.add_argument("-m", "--mode", choices=["CBC", "GCM"], default="CBC")
        parser.add_argument("-k", "--keystore", type=str, default=".keystore", help="path to the keystore")
        parser.add_argument("-p", "--password", type=str, help="password to the keystore")
        parser.add_argument("-i", "--identifier", type=str, help="key identifier", required=True)
        parser.add_argument("-v", "--verbosity", action="count", help="be more verbose please", default= 0)

        args = parser.parse_args()

        load_dotenv()
        handler = StreamHandler(sys.stdout)
        handler.setLevel(INFO - args.verbosity*10)
        c_format = Formatter('[%(name)s][%(levelname)s]: %(message)s')
        handler.setFormatter(c_format)
        logger.addHandler(handler)

        if not args.password:
            password = os.environ["KEYSTORE_PASSWORD"]
        else:
            password = args.password
        if not password:
            password = ""

        encryptor = Encryptor(args.password, args.mode, args.identifier, keystore_path = args.keystore)

        if args.encrypt:
            ct = encryptor.encrypt(args.encrypt[0], file=True, save_as=args.encrypt[1])
            if ct:
                logger.info(f"Succesfully encrypted file {args.encrypt[0]} and saved as {args.encrypt[1]}")
            else:
                logger.info(f"Failed to encrypt file {args.encrypt[0]}")
        elif args.decrypt:
            plaintext = encryptor.decrypt(args.decrypt[0], file=True, save_as=args.decrypt[1])
            if plaintext:
                logger.info(f"Succesfully decrypted file {args.decrypt[0]} and saved as {args.decrypt[1]}")
            else:
                logger.info(f"Failed to decrypt file {args.decrypt[0]}")
        elif args.challenge:
            pass
        elif args.oracle:
            pass

    except Exception as ex:
        logger.error(ex.args[0])