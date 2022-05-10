from operator import xor
import sys
from Crypto import Random
from logging import Logger, StreamHandler, WARNING, FileHandler, Formatter

AES_LEN=128


class distinguisher():
    def __init__(self, verbosity):
        logger = Logger("distinguisher")
        handler_file = FileHandler('file.log')
        handler_file.setLevel(WARNING - verbosity*10)
        f_format = Formatter('[%(asctime)s][%(name)s][%(levelname)s]: %(message)s')
        handler_file.setFormatter(f_format)
        logger.addHandler(handler_file)

        handler = StreamHandler(sys.stdout)
        handler.setLevel(WARNING - verbosity*10)
        c_format = Formatter('[%(name)s][%(levelname)s]: %(message)s')
        handler.setFormatter(c_format)
        logger.addHandler(handler)
        self.logger = logger

    def generate_challenge_messages(self):
        self.m0 = "0"*(AES_LEN//8)
        self.m1 = "1"*(AES_LEN//8)
        self.logger.info(f"Distinguisher generated m0,1 = {self.m0}, {self.m1}")

        return self.m0, self.m1

    def generate_winning_message(self, c_star):
        self.challenge = c_star
        iv = int.from_bytes(c_star.nonce_or_iv, "big")
        iv_plus_one = iv+1
        

        m0_as_number = int.from_bytes(self.m0.encode(), "big")
        self.logger.debug(f"m0 as number = {m0_as_number}")
        self.m2 = xor(xor(m0_as_number, iv), iv_plus_one)
        self.logger.debug(f"m0 xor iv xor iv+1 as number = {self.m2}")
        self.m2 = self.m2.to_bytes(len(self.m0), "big")
        
        self.logger.debug(f"Generated m2 as: {self.m2}")
        return self.m2

    def distinguish(self, c2):
        answer = self.m0 if c2.ctext == self.challenge.ctext else self.m1
        self.logger.debug(f"c*:{self.challenge.ctext}, c2:{c2.ctext}")
        self.logger.debug(f"Guessing mb as: {answer}")
        return answer