def hex_to_bits(hex_string: str) -> list[int]:
    """
    Converts a hexadecimal string to a list of bits.
    Example: "0f" -> [0,0,0,0,1,1,1,1]
    """
    bits = []
    for char in hex_string:
        val = int(char, 16)
        bits.extend([(val >> i) & 1 for i in reversed(range(4))])
    return bits

def bits_to_hex(bits: list[int]) -> str:
    """
    Converts a list of bits to a hexadecimal string.
    Example: [0,0,0,0,1,1,1,1] -> "0f" 
    """
    hex_string = ""
    for i in range(0, len(bits), 4):
        nibble = bits[i:i+4]
        val = 0
        for bit in nibble:
            val = (val << 1) | bit
        hex_string += format(val, 'x')
    return hex_string
