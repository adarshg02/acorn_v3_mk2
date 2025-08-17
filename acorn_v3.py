# acorn.py
from filter import FilterFunction
from feedback import FeedbackFunction
from state_update import update_state
class ACORN128:
    def __init__(self, key: list, iv: list):
        assert len(key) == 128 and len(iv) == 128
        self.state = [0] * 293
        self.initialize(key, iv)

    def initialize(self, key: list, iv: list):
        m = key + iv + [(key[0] ^ 1)] + [key[i % 128] for i in range(1, 1536)]
        ca = [1] * 1792
        cb = [1] * 1792
        for i in range(1792):
            mi = m[i]
            cai = ca[i]
            cbi = cb[i]
            self.state = update_state(self.state, cai, cbi, mi)

    def process_associated_data(self, ad_bits: list):
        adlen = len(ad_bits)
        # Prepare m: ad_bits followed by zeros to total length adlen+256
        m = ad_bits + [0] * 256
    
        # Prepare cai and cbi arrays
        cai = [1] * (adlen + 128) + [0] * 128  # total length: adlen + 256
        cbi = [1] * (adlen + 256)
    
        for i in range(adlen + 256):
            mi = m[i]
            self.state = update_state(self.state, cai[i], cbi[i], mi)

    def encrypt(self, plaintext_bits: list) -> list:
        ciphertext = []
    
        # 🔁 256 dummy steps between AD and PT
        for _ in range(256):
            self.state = update_state(self.state, 1, 0, 0)
    
        # Now do actual PT encryption
        for mi in plaintext_bits:
            z = FilterFunction.compute(self.state)
            ci = mi ^ z
            ciphertext.append(ci)
            self.state = update_state(self.state, 1, 0, mi)
    
        # 🔁 256 dummy steps after PT
        for _ in range(256):
            self.state = update_state(self.state, 0, 0, 0)
    
        return ciphertext



    def finalize(self) -> list:
        tag = []
        for i in range(768):
            z = FilterFunction.compute(self.state)
            self.state = update_state(self.state, 1, 1, 0)
            # Only collect the last 128 bits as tag
            if i >= 768 - 128:
                tag.append(z)
        return tag


    def encrypt_and_tag(self, plaintext_bits: list, ad_bits: list) -> tuple:
        self.process_associated_data(ad_bits)
        ciphertext = self.encrypt(plaintext_bits)
        tag = self.finalize()
        return ciphertext, tag
