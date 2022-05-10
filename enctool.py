#!/usr/bin/env python
import argparse
import sys
import os
import jks
import random
import pickle
import time
import blessed

from logging import Logger, StreamHandler, WARNING, FileHandler, Formatter
import distinguisher
from dotenv import load_dotenv
from dataclasses import dataclass
from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from collections import namedtuple


verb = 1
enc_text = namedtuple("enc_text", "ctext tag nonce_or_iv")
logger = Logger("encryptor_logger")
handler_file = FileHandler('file.log')
handler_file.setLevel(WARNING - verb*10)
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
        self.insecure_iv = Random.get_random_bytes(128//8)
        logger.debug("Generated insecure IV: ")
        logger.debug(self.insecure_iv)
        logger.debug("Encryptor initialized in AES-"+self.mode + " mode")
        pass

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
        key = custom_key if custom_key else self.private_key

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

        logger.debug("Encrypting message: ")
        logger.debug(message)
        
        if not isinstance(message, bytes):
            # encode end pad message
            message = message.encode()
        
        # Mode is GCM
        if self.mode == "GCM":
            encryptor = AES.new(key, AES.MODE_GCM)
            result = encryptor.encrypt_and_digest(message)
            ciphertext, tag = result
            nonce = encryptor.nonce
        # Mode is cBC
        elif self.mode == "CBC":
            message = pad(message, AES.block_size)
            encryptor = AES.new(key, AES.MODE_CBC)
            result = encryptor.encrypt(message)
            ciphertext = result
            tag = None
            nonce = encryptor.iv
        # Mode is insecure CBC
        elif self.mode == "ICBC":
            message = pad(message, AES.block_size)
            iv = int.from_bytes(self.insecure_iv, "big")
            iv += 1
            self.insecure_iv = iv.to_bytes(128//8, "big")
            logger.debug("Insecure iv: ")
            logger.debug(self.insecure_iv)
            encryptor = AES.new(key, AES.MODE_CBC, iv=self.insecure_iv)
            result = encryptor.encrypt(message)
            ciphertext = result
            tag = None
            nonce = encryptor.iv

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

        if self.mode == "CBC" or self.mode == "ICBC":
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
                plaintext = plaintext
            except ValueError as ex:
                logger.error(ex)
                return None

        try:
            plaintext = plaintext.decode()
            logger.debug(f"Decrypted message: \n{plaintext}")
        except Exception as ex:
            logger.error(ex)
            return None

        if save_as:
            with open(save_as, "w") as f:
                f.write(plaintext)

        return plaintext

    def oracle(self, messages):
        logger.info("Starting oracle...")

        logger.info("Output format is message:ciphertext")

        ctexts = []
        if not isinstance(messages, list):
            messages = [messages]

        for message in messages:
            ct = self.encrypt(message)    
            ctexts.append(ct)
        
        return ctexts

    def challenge(self, message0, message1):
        logger.info("Starting challenge...")
        random.seed(time.time() + int.from_bytes(Random.get_random_bytes(32), "big"))
        b = random.getrandbits(1)

        logger.debug(f"Chosen bit b={b}")
        if b == 0: 
            chosen_message = message0
            ct = self.encrypt(message0)
        if b == 1:
            chosen_message = message1
            ct = self.encrypt(message1)

        return chosen_message, ct

def CPA_game(term, oracle, distinguisher):
    logger.info("Starting CPA game with Distinguisher...")
    # First round - attacker generates two messages
    m0, m1 = distinguisher.generate_challenge_messages()
    #   m0, m1
    # D ------> O
    print(f"Round 1:")
    print(f"Attacker generated {term.blue(m0)} and {term.yellow(m1)}")

    # Oracle selects bit b at random and return challenge c*
    mb, c_star = oracle.challenge(m0, m1)
    #      c*
    # D <------ O
    print(f"Oracle selects challenge\n {term.orange(mb)}:{term.orange(str(c_star.ctext))}")

    # second round - attacker conjures a new message m2 =/= m0,m1
    # and asks oracle for encrypting it
    m2 = distinguisher.generate_winning_message(c_star)

    assert m2 != m1 and m2 != m0, "Newly generated message is the same as challenge messages!"

    logger.info(f"m2 from distingusher: {m2}")
    print(f"Attacker generates a new message {term.pink(m2.decode(errors='replace'))}")
    c2 = oracle.oracle(m2)[0]
    print(f"Oracle encrypts newly generated message \n {term.pink(m2.decode(errors='replace'))}:{term.pink(str(c2.ctext))}")
    #      m2
    # D ------> O
    #      c2
    # D <------ O

    # attacker now can decide if m0 or m1 was the challenge
    m_guess = distinguisher.distinguish(c2)
    logger.info(f"mb guessed by distinguisher: {m_guess}")
    # D outputs m_guess
    if m_guess == mb:
        print(term.green("Attacker won!"))
        return True
    else:
        print(term.red(f"Attacker lost!"))
        return False


if __name__=="__main__":
    try:
        term = blessed.Terminal()
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-d", "--decrypt", type=str, nargs=2, help="decrypt file(s) on disk")
        group.add_argument("-e", "--encrypt", type=str, nargs=2, help="encrypt file(s) on disk")
        group.add_argument("-c", "--challenge", type=str, nargs=2, help="challenge mode - on input [m0, m1] pick independently, \
    uniformly at random a bit b and return a ciphertext cb of a message mb")
        group.add_argument("-o", "--oracle", type=str, nargs='+', help="oracle mode - on input consisting of q messages, return q ciphertexts")
        group.add_argument("-g", "--cpagame", action="count", help="Play CPA game with distinguisher", default=0)


        parser.add_argument("-m", "--mode", choices=["CBC", "GCM", "ICBC"], default="CBC")
        parser.add_argument("-k", "--keystore", type=str, default=".keystore", help="path to the keystore")
        parser.add_argument("-p", "--password", type=str, help="password to the keystore")
        parser.add_argument("-i", "--identifier", type=str, help="key identifier", required=True)
        parser.add_argument("-v", "--verbosity", action="count", help="be more verbose please", default= 0)

        args = parser.parse_args()

        load_dotenv()
        handler = StreamHandler(sys.stdout)
        handler.setLevel(WARNING - args.verbosity*10)
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
                print(f"Succesfully encrypted file {args.encrypt[0]} and saved as {args.encrypt[1]}")
            else:
                logger.info(f"Failed to encrypt file {args.encrypt[0]}")
                print(f"Failed to encrypt file {args.encrypt[0]}")
        elif args.decrypt:
            plaintext = encryptor.decrypt(args.decrypt[0], file=True, save_as=args.decrypt[1])
            if plaintext:
                logger.info(f"Succesfully decrypted file {args.decrypt[0]} and saved as {args.decrypt[1]}")
                print(f"Succesfully decrypted file {args.decrypt[0]} and saved as {args.decrypt[1]}")
            else:
                logger.info(f"Failed to decrypt file {args.decrypt[0]}")
                print(f"Failed to decrypt file {args.decrypt[0]}")
        elif args.challenge:
            mess, challenge = encryptor.challenge(args.challenge[0], args.challenge[1])
            print(f"{term.red(mess)}:{challenge}")
        elif args.oracle:
            logger.debug(f"Parsing messages: {args.oracle}")
            if isinstance(args.oracle, str):
                messages = [args.oracle]
            else:
                messages = args.oracle
            ct = encryptor.oracle(messages)
            for i in range(len(ct)):
                print(f"{term.blue(messages[i])}:{ct[i]}")
        elif args.cpagame:
            dist = distinguisher.distinguisher(args.verbosity)
            CPA_game(term, encryptor, dist)


    except Exception as ex:
        logger.error(ex.args[0])