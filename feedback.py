from filter import FilterFunction
class FeedbackFunction:
    @staticmethod
    def compute(state_bits: list, ca: int, cb: int, input_bit: int) -> int:
        
        s = state_bits
        if len(s) != 293:
            raise ValueError("State must be 293 bits.")

        filter_bit = FilterFunction.compute(s)

        nonlinear_part = (s[0] ^ (1-s[107]) ^ FilterFunction.maj(s[244], s[23], s[160]))

        return (nonlinear_part ^ (ca & s[196]) ^ (cb & filter_bit))
