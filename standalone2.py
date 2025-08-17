from utils import bits_to_hex
z = 0
def maj(a, b, c):
    return((a&b) ^ (a&c) ^ (b&c))

def ch(a, b, c):
    return((a&b) ^ ((1-a)&c))

def filter(state: list) -> int:
    s = state
    if len(s) != 293:
        raise ValueError("State must be 293 bits.")
    return(s[12] ^ s[154] ^ maj(s[235], s[61], s[193]) ^ ch(s[230], s[111], s[60])) 

def feedback(state: list, cai: int, cbi: int, z):
    s = state
    if len(s) != 293:
        raise ValueError("State must be 293 bits")
    nonlinear_part = (s[0] ^ (1-s[107]) ^ maj(s[244], s[23], s[160]))
    return (nonlinear_part ^ (cai & s[196]) ^ (cbi & z))

def state_update(state: list, mi: int, cai: int, cbi: int):
    global z
    s = state[:]
    #step 1
    s[289] ^= s[235] ^ s[230]
    s[230] ^= s[196] ^ s[193]
    s[193] ^= s[160] ^ s[154]
    s[154] ^= s[111] ^ s[107]
    s[107] ^= s[66] ^ s[61]
    s[61] ^= s[23] ^ s[0]

    #step 2
    z = filter(s)

    #step 3
    feedback_bit = feedback(s, cai, cbi, z)

    #step 4
    new_state = s[1:] + [(feedback_bit ^ mi) & 1]
    return new_state

def initializtion(state: list, key: list, iv: list, ad_bits: list):
    #state = [0] * 293
    m = key + iv + [key[0] ^ 1] + [key[i%128] for i in range(1, 1536)]
    ca = [1] * 1792
    cb = [1] * 1792
    for i in range(1792):
        mi = m[i]
        cai = ca[i]
        cbi = cb[i]
        state = state_update(state, mi, cai, cbi)
    
    adlen = len(ad_bits)     
    adlen = len(ad_bits)
    m = ad_bits + [1] + [0] * 255  # Pad AD with '1' followed by 255 '0's
    cai = [1] * (adlen + 128) + [0] * 128  # cai = 1 for (adlen + 128) steps, then 0
    cbi = [1] * (adlen + 256)  # cbi = 1 for (adlen + 256) steps

    for i in range(adlen + 256):
        mi = m[i]
        state = state_update(state, mi, cai[i], cbi[i])
    
    return state

def encrypt(state: list, plaintext_bits: list):
    ciphertext = []
    z_list = []
    for _ in range(256):
        state = state_update(state, 1, 0, 0)

    for mi in plaintext_bits:
        z_list.append(z)
        ci = mi ^ z
        ciphertext.append(ci)
        state = state_update(state, mi, 1, 0)
    
    for _ in range(256):
        state = state_update(state, 0, 0 ,0)
    return ciphertext, z_list

if __name__ == "__main__":
    key = [0] * 128
    iv = [0] * 128  
    pt = [0] * 7 + [1]
    ad = []

    #ciphertext = bits_to_hex(encrypt(key, iv, pt, ad))
    #print(ciphertext)


