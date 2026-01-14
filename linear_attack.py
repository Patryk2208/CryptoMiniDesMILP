import random
from full_des import DES
from des_milp_solver import DES_MILP_Linear
import sbox_tables

class LinearAttack:
    def __init__(self):
        # P Table for undoing permutation P in partial decryption
        self.P = DES.P_TABLE
        self.des = None # Placeholder

    def compute_parity(self, value, mask):
        """
        Computes parity of (value & mask).
        Returns 0 or 1.
        """
        return bin(value & mask).count('1') % 2

    def get_active_sboxes_and_mask(self, output_mask_l):
        """
        Input: output_mask_l (Gamma_L2)
        
        We need equality:
        P . Gamma_P + L2 . Gamma_L2 + R2 . Gamma_R2 = 0
        Substitute L2 = R3 ^ f(L3, K3)
        P . Gamma_P + (R3 ^ f(L3, K3)) . Gamma_L2 + L3 . Gamma_R2 = 0
        
        Term involving K3 is: f(L3, K3) . Gamma_L2
        This is: P(S(E(L3) ^ K3)) . Gamma_L2
        Move P inside: S(E(L3) ^ K3) . P_inv(Gamma_L2)
        
        Let Gamma_S_out = P_inv(Gamma_L2)
        
        We need to identify which S-boxes have non-zero Gamma_S_out part.
        Returns: 
            active_sboxes: list of indices (0..7)
            sbox_out_masks: list of 4-bit masks for EACH active sbox
        """
        # 1. Inverse Permutation P on Gamma_L2
        # P_TABLE maps input bit idx to output bit idx: output[i] = input[P[i]-1]
        # Linear property: A . P(B) = P_inv(A) . B
        # Let Y = P(X). Y[i] = X[P[i]-1].
        # Mask_Y . Y = Sum Mask_Y[i] * Y[i] = Sum Mask_Y[i] * X[P[i]-1].
        # So Mask_X[k] gets contribution from Mask_Y[i] where P[i]-1 == k.
        # Since P is bijection, for each k there is unique i.
        # So Mask_X[P[i]-1] = Mask_Y[i].
        
        gamma_s_out = 0
        for i in range(32): # i is output index (0..31)
            # Check bit i of output_mask_l
            if (output_mask_l >> (31 - i)) & 1:
                # Corresponds to input bit P[i]-1
                input_pos = self.P[i] - 1
                gamma_s_out |= (1 << (31 - input_pos))
                 
        active_sboxes = []
        sbox_out_masks = {}
        
        for i in range(8):
            # Extract 4-bit mask for S-box i
            # S-box i outputs bits 4*i to 4*i+3 (0-indexed, MSB first)
            # So shift = 32 - 4*(i+1) ?
            # Total 32 bits.
            # i=0 (S1) -> bits 0,1,2,3 (MSB).
            # shift for bit 0 is 31.
            # shift for bit 3 is 28.
            # So shift = 32 - 4 - 4*i = 28 - 4*i.
            
            shift = 28 - 4*i
            mask_chunk = (gamma_s_out >> shift) & 0xF
            
            if mask_chunk != 0:
                active_sboxes.append(i)
                sbox_out_masks[i] = mask_chunk
                
        return active_sboxes, sbox_out_masks

    def partial_decryption(self, L3, active_sboxes, subkeys, sbox_out_masks):
        """
        Compute parity of f(L3, subkeys) . sbox_out_masks
        Only for active S-boxes.
        
        subkeys: dictionary {sbox_idx: 6-bit key}
        """
        parity = 0
        
        # Expand L3 to 48 bits
        # We need a DES instance or static method permuate. DES instance is cleaner.
        # self.des is now available after run_attack starts.
        expanded = self.des.permute(L3, DES.E_TABLE, 32)
        
        for idx in active_sboxes:
             # Extract 6-bit input for S-box idx
             # Bits idx*6 to (idx+1)*6
             # MSB is bit 0.
             # shift = 48 - 6 - 6*idx = 42 - 6*idx
             shift = 42 - 6*idx
             input_chunk = (expanded >> shift) & 0x3F
             
             # XOR with subkey guess
             key_chunk = subkeys[idx]
             s_in = input_chunk ^ key_chunk
             
             # S-box lookup
             # s_in is 6 bits
             # DES.S_BOXES is static
             row = ((s_in >> 5) & 1) * 2 + (s_in & 1)
             col = (s_in >> 1) & 0x0F
             s_out_val = DES.S_BOXES[idx][row][col]
             
             # Parity with mask
             mask = sbox_out_masks[idx]
             p = self.compute_parity(s_out_val, mask)
             parity ^= p
             
        return parity

    def run_attack(self, num_samples=10000):
        print(f"Running Linear Attack with {num_samples} samples...")
        
        # 1. Get characteristic from MILP
        solver = DES_MILP_Linear(rounds=2)
        res = solver.solve()
        if not res:
            print("Failed to find characteristic.")
            return

        input_mask_L, input_mask_R = res['input_mask_L'], res['input_mask_R']
        output_mask_L, output_mask_R = res['output_mask_L'], res['output_mask_R']
        
        print(f"Characteristic found.")
        print(f"Gamma_P (L0, R0) = ({hex(input_mask_L)}, {hex(input_mask_R)})")
        print(f"Gamma_L2 = {hex(output_mask_L)}")
        
        if output_mask_L == 0:
            print("Gamma_L2 is 0. Cannot recover key bits (Distinguisher only).")
            return

        active_sboxes, sbox_out_masks = self.get_active_sboxes_and_mask(output_mask_L)
        print(f"Active S-boxes in Round 3: {active_sboxes}")
        print(f"S-box Output Masks (before P): {sbox_out_masks}")
        
        # 2. Generate Data
        print("Generating Plantext-Ciphertext pairs...")
        pairs = []
        # Random key
        key = random.getrandbits(64)
        print(f"True Key: {hex(key)}")
        
        # Init DES with TRUE KEY and 3 ROUNDS
        self.des = DES(key, rounds=3)
        
        # Derive round 3 subkey parts for verification
        # Key schedule is generated in __init__
        subkeys_all = self.des.keys
        k3 = subkeys_all[2] # Round 3 key (0-indexed -> 2)
        # Extract 6-bit chunks for active sboxes
        true_subkeys = {}
        # k3 is 48 bits.
        for idx in active_sboxes:
             shift = 42 - 6*idx
             true_subkeys[idx] = (k3 >> shift) & 0x3F
        print(f"True Subkeys for active S-boxes: {true_subkeys}")

        for _ in range(num_samples):
            pt = random.getrandbits(64)
            ct = self.des.encrypt(pt) # 3-round encryption using self.des
            pairs.append((pt, ct))
            
        # 3. Key Recovery
        if len(active_sboxes) > 4:
            print("Warning: Too many active S-boxes to brute force simultaneously.")
            
        import itertools
        key_guesses = list(itertools.product(range(64), repeat=len(active_sboxes)))
        
        best_key = None
        max_bias = -1
        
        print(f"Testing {len(key_guesses)} key candidates...")
        
        processed_pairs = []
        for pt, ct in pairs:
            # Separate L0, R0 (from pt)
            l0r0 = self.des.permute(pt, DES.IP_TABLE, 64)
            L0 = (l0r0 >> 32) & 0xFFFFFFFF
            R0 = l0r0 & 0xFFFFFFFF
            
            # Ciphertext CT -> IP_inv -> R3, L3
            # In full_des.py: pre_output = (R << 32) | L. 
            # permute(pre_output, FP_TABLE).
            # So CT = IP_inv(R3 | L3).
            # So R3 | L3 = IP(CT).
            # Use IP_TABLE to reverse IP_inv? No.
            # IP_TABLE is inverse of FP_TABLE.
            # So IP(CT) should give R3 | L3.
            
            r3l3 = self.des.permute(ct, DES.IP_TABLE, 64)
            
            # r3l3 = (R3 << 32) | L3
            R3 = (r3l3 >> 32) & 0xFFFFFFFF
            L3 = r3l3 & 0xFFFFFFFF
            
            # Fixed Parity:
            # P.Gamma_P + L3.Gamma_R2 + (R3).Gamma_L2 + ...
            # Wait previously: P.Gamma_P + L2.Gamma_L2 + R2.Gamma_R2 = 0
            # Substitute L2 = R3 ^ f(L3, K)
            # Substitute R2 = L3
            # P.Gamma_P + (R3 ^ f(L3, K)).Gamma_L2 + L3.Gamma_R2 = 0
            # P.Gamma_P + R3.Gamma_L2 + L3.Gamma_R2 + f(L3, K).Gamma_L2 = 0
            
            fixed_parity = self.compute_parity(L0, input_mask_L) ^ \
                           self.compute_parity(R0, input_mask_R) ^ \
                           self.compute_parity(R3, output_mask_L) ^ \
                           self.compute_parity(L3, output_mask_R)
                           
            processed_pairs.append((fixed_parity, L3))
            
        # Iterate Guesses
        for guess_tuple in key_guesses:
            # Construct subkey map
            subkeys = {active_sboxes[i]: guess_tuple[i] for i in range(len(active_sboxes))}
            
            count_zeros = 0
            
            for fixed_p, L3 in processed_pairs:
                # Key dependent part: f(L3, K).Gamma_L2
                k_parity = self.partial_decryption(L3, active_sboxes, subkeys, sbox_out_masks)
                
                total_parity = fixed_p ^ k_parity
                if total_parity == 0:
                    count_zeros += 1
                    
            bias = abs(count_zeros - num_samples / 2)
            if bias > max_bias:
                max_bias = bias
                best_key = subkeys
                
        print(f"Best Key Found: {best_key}")
        print(f"Max Bias: {max_bias}")
        
        # Verify
        match = True
        for idx in active_sboxes:
            if best_key[idx] != true_subkeys[idx]:
                match = False
                print(f"Mismatch at S-box {idx}: Expected {true_subkeys[idx]}, Got {best_key[idx]}")
        
        if match:
            print("SUCCESS: Key bits recovered successfully!")
        else:
            print("FAILURE: Key recovery failed.")

if __name__ == "__main__":
    attack = LinearAttack()
    attack.run_attack(num_samples=20000)
