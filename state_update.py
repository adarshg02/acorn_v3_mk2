from feedback import FeedbackFunction
from filter import FilterFunction
def update_state(state_bits: list, ca: int, cb: int, input_bit: int) -> list:
    """
    Updates ACORN v3's 293-bit state.

    Steps:
      1. Update 6 taps with LFSR-like logic (per spec pseudocode)
      2. Compute keystream (for cb control)
      3. Compute feedback bit with ca/cb/mi (or ai)
      4. Shift left and inject feedback
    """
    s = state_bits[:]

    # Step 1: Tap update
    s[289] ^= s[235] ^ s[230]
    s[230] ^= s[196] ^ s[193]
    s[193] ^= s[160] ^ s[154]
    s[154] ^= s[111] ^ s[107]
    s[107] ^= s[66] ^ s[61]
    s[61] ^= s[23] ^ s[0]

    # Step 2: Keystream bit generated via FilterFunction (updated in the feedback.py)
    # Step 3: Compute feedback
    feedback_bit = FeedbackFunction.compute(s, ca, cb, input_bit)
  
    # Step 4: Shift state and inject feedback_bit ^ input_bit at the end
    new_state = s[1:] + [(feedback_bit ^ input_bit) & 1]
    return new_state

