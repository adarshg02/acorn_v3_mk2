class FilterFunction:
    @staticmethod
    def maj(a, b, c):
        return((a&b) ^ (a&c) ^ (b&c))
    
    @staticmethod
    def ch(a, b, c):
        return((a&b) ^ ((1-a)&c))
    @staticmethod  
    def compute(state_bits: list) -> int:
        s = state_bits
        if len(s) != 293:
            raise ValueError("State must be 293 bits.")

        return(s[12] ^ s[154] ^ FilterFunction.maj(s[235], s[61], s[193]) ^ FilterFunction.ch(s[230], s[111], s[60])) & 1   
    #     return (
    #     s[12] ^ s[66] ^ s[107] ^ s[111] ^ s[154] ^
    #     ((s[61] ^ s[23] ^ s[0]) & (s[193] ^ s[160] ^ s[154])) ^
    #     ((s[61] ^ s[23] ^ s[0] ^ s[193] ^ s[160] ^ s[154]) & s[235]) ^
    #     ((s[66] ^ s[111]) & (s[230] ^ s[193] ^ s[196]))
    # )