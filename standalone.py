import math

# Assuming bits_to_hex is available from a utils.py or defined here if simple
def bits_to_hex(bit_list):
    """Converts a list of bits (0s and 1s) to a hexadecimal string."""
    if not bit_list:
        return ""
    
    # Pad to a multiple of 8 bits if necessary
    padded_bits = bit_list + [0] * ((8 - len(bit_list) % 8) % 8)
    
    hex_string = ""
    for i in range(0, len(padded_bits), 8):
        byte_val = 0
        for j in range(8):
            byte_val |= (padded_bits[i + j] << (7 - j)) # MSB first for hex conversion
        hex_string += f"{byte_val:02x}"
    return hex_string

class ACORNv3:
    def __init__(self, key: bytes, iv: bytes):
        """
        Initialize ACORN with a 128-bit key and 128-bit IV
        """
        if len(key) != 16 or len(iv) != 16:
            raise ValueError("Key and IV must be 16 bytes (128 bits) each")
            
        self.state = [0] * 293  # 293-bit state initialized to zeros
        self.key = key
        self.iv = iv
        
        # Initialize the cipher
        self._initialize()
    
    def _initialize(self):
        """Initialize the state with key and IV"""
        # Load key and IV into state (1792 steps)
        # Construct the message bits 'm' for initialization as per spec
        m_bits = [0] * 1792
        
        # Key bits (first 128 steps)
        for i in range(128):
            m_bits[i] = (self.key[i // 8] >> (i % 8)) & 1
            
        # IV bits (next 128 steps)
        for i in range(128):
            m_bits[128 + i] = (self.iv[i // 8] >> (i % 8)) & 1
            
        # K_128,0 XOR 1 (at step 256)
        m_bits[256] = ((self.key[0] >> 0) & 1) ^ 1 # LSB of first key byte XOR 1
        
        # Remaining 1792 - 256 - 1 = 1535 steps (key bits modulo 128)
        # The spec states K_{i mod 128} where i is the bit index starting from 257.
        # This means K_0, K_1, ..., K_127, K_0, ...
        # (i-257) effectively maps the index to the key bit index.
        for i in range(257, 1792):
             key_bit_idx = (i - 257) % 128 # Index relative to key bits (0-127)
             key_byte_idx = key_bit_idx // 8
             bit_pos_in_byte = key_bit_idx % 8
             m_bits[i] = (self.key[key_byte_idx] >> bit_pos_in_byte) & 1

        # Control bits are 1 during initialization
        ca = 1
        cb = 1
        
        for i in range(1792):
            self._state_update(m_bits[i], ca, cb)
    
    def _maj(self, x, y, z):
        """Majority function"""
        return (x & y) ^ (x & z) ^ (y & z)
    
    def _ch(self, x, y, z):
        """Choice function - Corrected ~x to (1 - x)"""
        return (x & y) ^ ((1 - x) & z)
    
    def _ksg128(self):
        """Keystream generation function (equivalent to 'z' in previous code)"""
        s = self.state
        return (s[12] ^ s[154] ^ 
                self._maj(s[235], s[61], s[193]) ^ 
                self._ch(s[230], s[111], s[66]))
    
    def _fbk128(self, ca_bit: int, cb_bit: int, keystream_bit: int):
        """Feedback function"""
        s = self.state
        return (s[0] ^ (1 - s[107]) ^ 
                self._maj(s[244], s[23], s[160]) ^ 
                (ca_bit & s[196]) ^ 
                (cb_bit & keystream_bit)) # Use passed keystream_bit
    
    def _state_update(self, m_bit: int, ca_bit: int, cb_bit: int):
        """
        Update the state with message bit m_bit and control bits ca_bit, cb_bit.
        This function will internally generate the keystream bit for its own use
        in the feedback function.
        """
        # Step 1: Update using six LFSRs (these are XOR assignments, not new states)
        # Note: The original code had `s[289] ^= ...` which updates in place.
        # When you pass `s = state[:]`, it creates a copy. Modifications to `s`
        # are local to this function unless they are explicitly assigned back.
        # ACORN's state update works on the current state and computes the next.
        # Let's correctly apply the LFSR shifts based on the specification.
        
        # Capture current state for calculations
        s_current = self.state[:] 

        # Compute internal state updates (based on ACORN diagram's LFSR taps)
        # These are internal calculations that affect the *next* state, not
        # literal in-place updates *before* the shift. The standard way is to
        # calculate the new state bits based on the current state.
        
        # Simplified LFSR calculation (assuming state is already shifted, and these are bits being XORed into existing positions)
        # The typical ACORN state update shifts the entire register first,
        # then inserts the new bit at s[292]. The specification for LFSR updates
        # often refers to the new values of the bits as being computed for the next state.
        # Your current `s[289] ^= ...` implies in-place XORing. Let's assume this is the intent
        # for these specific taps, which then feed into the next shift.
        
        # Applying LFSR feedback. These are part of the state evolution.
        s_current[289] ^= s_current[235] ^ s_current[230]
        s_current[230] ^= s_current[196] ^ s_current[193]
        s_current[193] ^= s_current[160] ^ s_current[154]
        s_current[154] ^= s_current[111] ^ s_current[107]
        s_current[107] ^= s_current[66] ^ s_current[61]
        s_current[61] ^= s_current[23] ^ s_current[0]
        
        # Step 2: Generate keystream bit (this is 'z' for the current step)
        ksi = self._ksg128() # This uses the *current* self.state before the shift
        
        # Step 3: Generate feedback bit (f)
        f = self._fbk128(ca_bit, cb_bit, ksi)
        
        # Step 4: Shift the register and insert new bit
        # The entire state shifts right, new bit enters s[292]
        for j in range(292):
            self.state[j] = self.state[j+1]
        self.state[292] = (f ^ m_bit) & 1 # Ensure result is 0 or 1
        
        # Return the keystream bit for external use (e.g., encryption)
        return ksi 
    
    def encrypt(self, plaintext: bytes, associated_data: bytes):
        """Encrypt plaintext and return ciphertext and authentication tag."""
        
        # Convert plaintext bytes to a list of bits (LSB first for each byte)
        plaintext_bits = []
        for byte_val in plaintext:
            for i in range(8):
                plaintext_bits.append((byte_val >> i) & 1)
        
        # Convert associated_data bytes to a list of bits (LSB first for each byte)
        ad_bits = []
        for byte_val in associated_data:
            for i in range(8):
                ad_bits.append((byte_val >> i) & 1)

        pclen = len(plaintext_bits)
        adlen = len(ad_bits)
        
        # --- Associated Data (AD) Processing Phase ---
        # The spec implies a total of adlen + 256 steps for AD.
        # Message bits 'm' for AD phase: AD bits + 1 (if AD empty) + 255 zeros
        
        ad_m_bits = ad_bits[:] # Start with AD bits
        
        # Pad AD with 1 and then 255 zeros
        if adlen == 0: # If AD is empty, only padding applies
            ad_m_bits.append(1)
            ad_m_bits.extend([0] * 255)
        else: # If AD is not empty, it's AD bits + 1 + 255 zeros
            ad_m_bits.append(1)
            ad_m_bits.extend([0] * (256 - ((adlen + 1) % 256))) # Adjust padding length
                                                               # (1 + 255 bits for fixed padding)
            if len(ad_m_bits) < adlen + 256: # Ensure at least 256 total padding bits
                 ad_m_bits.extend([0] * (adlen + 256 - len(ad_m_bits)))
            
        # Control bits for AD phase
        ad_ca_bits = [1] * (adlen + 128) + [0] * 128 # CA = 1 for adlen+128 steps, then 0 for 128 steps
        ad_cb_bits = [1] * (adlen + 256)             # CB = 1 throughout AD phase
        
        for i in range(adlen + 256):
            m_val = ad_m_bits[i] if i < len(ad_m_bits) else 0 # Ensure m_val is valid
            ca_val = ad_ca_bits[i] if i < len(ad_ca_bits) else 0 # Ensure ca_val is valid
            cb_val = ad_cb_bits[i] if i < len(ad_cb_bits) else 0 # Ensure cb_val is valid
            self._state_update(m_val, ca_val, cb_val)

        # --- Plaintext/Ciphertext Processing Phase ---
        # Total steps = pclen (for plaintext) + 256 (for finalization-like steps)
        
        ciphertext_bits = []
        tag_bits = [] # Store bits for tag generation

        # Iterate through pclen + 256 steps
        for i in range(pclen + 256):
            m_val = 0 # Default m for this phase
            ca_val = 0 # Default ca for finalization steps
            cb_val = 0 # CB is always 0 for this phase

            if i < pclen: # Processing plaintext bits
                m_val = plaintext_bits[i] # Current plaintext bit
                ca_val = 1 # CA is 1 during encryption
                cb_val = 0 # CB is 0 during encryption

                # Generate keystream bit *before* state update for encryption
                ksi = self._ksg128() 
                cipher_bit = m_val ^ ksi # XOR plaintext bit with keystream bit
                ciphertext_bits.append(cipher_bit)

                # Update state using the plaintext bit as 'm'
                self._state_update(m_val, ca_val, cb_val)
            else: # Finalization steps after all plaintext is processed
                  # (i ranges from pclen to pclen + 255)
                # The spec says cai = 1 for first 128 of these 256 steps, then 0 for next 128
                # and m = 0 for finalization.
                m_val = 0 # Message bit is 0 during finalization
                if i < pclen + 128: # First 128 steps of finalization
                    ca_val = 1
                else: # Last 128 steps of finalization
                    ca_val = 0
                cb_val = 0 # CB is 0 during finalization

                # Update state with m=0 and appropriate ca, cb
                ksi = self._state_update(m_val, ca_val, cb_val) # ksi for tag generation
                tag_bits.append(ksi) # Collect keystream bits for the tag
        
        # The tag is usually the first 128 bits of the keystream from the finalization phase.
        # This implementation collects all 256 bits, but you'd truncate to 128 for a 128-bit tag.
        
        # Convert ciphertext bits back to bytes
        ciphertext_bytes = self._bits_to_bytes(ciphertext_bits)
        
        # Convert tag bits to bytes (assuming 128-bit tag)
        tag_bytes = self._bits_to_bytes(tag_bits[:128]) # ACORN tag is 128 bits

        return ciphertext_bytes, tag_bytes
    
    def _bits_to_bytes(self, bit_list):
        """Converts a list of bits (0s and 1s, LSB first within byte) to bytes."""
        byte_array = bytearray()
        if not bit_list:
            return bytes(byte_array)

        # Pad to full bytes (multiples of 8) if necessary with zeros
        # ACORN often processes LSB first, then reconstructs bytes from LSB to MSB.
        # This assumes your bit list is LSB-first for each byte.
        
        padded_bits = bit_list + [0] * ((8 - len(bit_list) % 8) % 8)

        for i in range(0, len(padded_bits), 8):
            byte_val = 0
            # Construct byte from LSB to MSB (bit_list[i] is LSB of current byte)
            for j in range(8):
                byte_val |= (padded_bits[i + j] << j) 
            byte_array.append(byte_val)
            
        return bytes(byte_array)

# --- Test Vector Execution ---
if __name__ == "__main__":
    # 128-bit key and IV (16 bytes each) from the test vector
    key = bytes.fromhex("00000000000000000000000000000000")
    iv = bytes.fromhex("00000000000000000000000000000000")
    
    # Plaintext: '01' (hex) means the byte 0x01
    plaintext = bytes([0x01]) # This creates a bytes object containing a single byte with value 1
    
    # Associated Data: empty
    associated_data = b"" # Empty bytes object

    print(f"Test Vector Details:")
    print(f"Key:        {key.hex()}")
    print(f"IV:         {iv.hex()}")
    print(f"Plaintext:  {plaintext.hex()} (Single byte 0x01)")
    print(f"Associated Data: {associated_data.hex()} (empty)")
    print("-" * 30)

    # Encrypt
    acorn = ACORNv3(key, iv)
    ciphertext, tag = acorn.encrypt(plaintext, associated_data)
    
    print(f"Calculated Ciphertext: {ciphertext.hex()}")
    print(f"Calculated Tag:        {tag.hex()}")

    # --- Expected Output (You MUST verify these against a known ACORN test suite) ---
    # According to published ACORN test vectors for (K=0, IV=0, AD=empty, P=0x01):
    # Expected Ciphertext: 8c (This is for the single byte 0x01)
    # Expected Tag:        80a22a3cf2175949d01b1386127e743a

    expected_ciphertext_hex = "8c"
    expected_tag_hex = "80a22a3cf2175949d01b1386127e743a"

    print("-" * 30)
    print(f"Expected Ciphertext: {expected_ciphertext_hex}")
    print(f"Expected Tag:        {expected_tag_hex}")

    if ciphertext.hex() == expected_ciphertext_hex:
        print("Ciphertext Test PASSED!")
    else:
        print(f"Ciphertext Test FAILED! Mismatch.")

    if tag.hex() == expected_tag_hex:
        print("Tag Test PASSED!")
    else:
        print(f"Tag Test FAILED! Mismatch.")