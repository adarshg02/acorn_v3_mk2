from acorn_v3 import ACORN128
from utils import hex_to_bits, bits_to_hex

def read_test_vector(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    key_hex = iv_hex = pt_hex = ct_expected_hex = ""

    for line in lines:
        if line.startswith("Key ="):
            key_hex = line.strip().split('=')[1].strip()
        elif line.startswith("IV ="):
            iv_hex = line.strip().split('=')[1].strip()
        elif line.startswith("PT ="):
            pt_hex = line.strip().split('=')[1].strip()
        elif line.startswith("CT ="):
            ct_expected_hex = line.strip().split('=')[1].strip()

    return key_hex, iv_hex, pt_hex, ct_expected_hex

def test_vector(filepath):
    key_hex, iv_hex, pt_hex, ct_expected_hex = read_test_vector(filepath)

    key_bits = hex_to_bits(key_hex)
    iv_bits = hex_to_bits(iv_hex)
    pt_bits = hex_to_bits(pt_hex)

    if not (key_bits and iv_bits):
        print("Invalid key or IV. Check input format.")
        return

    cipher = ACORN128(key_bits, iv_bits)
    ct_generated_bits, _ = cipher.encrypt_and_tag(pt_bits, [])  # Empty associated data
    ct_generated_hex = bits_to_hex(ct_generated_bits)

    if ct_generated_hex.lower() == ct_expected_hex.lower():
        print("Test Passed ✅")
    else:
        print("Test Failed ❌")
        print(f"Expected: {ct_expected_hex}")
        print(f"Got     : {ct_generated_hex}")

if __name__ == '__main__':
    test_vector("D:/projects/ACORN_V3/acorn_v3_MK2/test_vectors.txt")
