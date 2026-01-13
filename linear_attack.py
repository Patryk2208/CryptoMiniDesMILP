"""
Linear Cryptanalysis Attack on DES
===================================
Based on Section 3 and 7 of the documentation.

Uses MILP solver to find optimal linear approximations, then performs
statistical attack to recover key fragments.
"""

import random
from full_des import DES
from des_milp_solver import DES_MILP_Linear


def get_parity(value, mask):
    """Calculate parity (XOR) of bits selected by mask."""
    masked = value & mask
    return bin(masked).count('1') % 2


def linear_attack(rounds=3, n_pairs=20000, secret_key=0x133457799BBCDFF1, use_milp=True):
    """
    Perform linear cryptanalysis attack on DES.
    
    Args:
        rounds: Number of DES rounds (default 3 for demonstration)
        n_pairs: Number of plaintext-ciphertext pairs to collect
        secret_key: The secret key to attack
        use_milp: Whether to use MILP solver for optimal mask (True) or fallback mask (False)
    
    Returns:
        Tuple of (best_key_candidate, true_key_fragment, success)
    """
    cipher = DES(secret_key, rounds=rounds)
    target_subkey = cipher.keys[rounds - 1]
    
    print(f"=== LINEAR ATTACK ({rounds} rounds) ===")
    print(f"Target subkey K{rounds}: {target_subkey:012x}")
    
    # Step 1: Use MILP to find optimal linear approximation
    if use_milp:
        print("\n[1] Using MILP to find optimal linear approximation...")
        milp_solver = DES_MILP_Linear(rounds=rounds - 1)  # Attack n-1 rounds
        mask_in, mask_out = milp_solver.solve()
        
        # Extract mask for plaintext (input to cipher)
        MASK_P = mask_in
        MASK_OUT_L = (mask_out >> 32) & 0xFFFFFFFF
        MASK_OUT_R = mask_out & 0xFFFFFFFF
    else:
        # Fallback: Use known good approximation for S5 (Matsui's attack)
        print("\n[1] Using known good mask (S5 approximation)...")
        MASK_P = 0x0000000000008000  # Targets S5
        MASK_OUT_L = 0x00008000
        MASK_OUT_R = 0x00000000
    
    print(f"    Input mask (plaintext):  {MASK_P:016x}")
    print(f"    Output mask: L={MASK_OUT_L:08x}, R={MASK_OUT_R:08x}")
    
    # Determine which S-box to attack based on mask
    # For now, we attack S5 (index 4) as it has the best bias per sbox_tables analysis
    sbox_idx = 4
    print(f"    Attacking S-box: S{sbox_idx + 1}")
    
    # Step 2: Collect plaintext-ciphertext pairs
    print(f"\n[2] Collecting {n_pairs} plaintext-ciphertext pairs...")
    data_pairs = []
    for _ in range(n_pairs):
        p = random.getrandbits(64)
        c = cipher.encrypt(p)
        data_pairs.append((p, c))
    
    # Step 3: Statistical analysis - test all 64 possible 6-bit key fragments
    print("\n[3] Performing statistical analysis...")
    biases = [0.0] * 64
    
    for k_guess in range(64):
        count_match = 0
        
        for P, C in data_pairs:
            # Parity of plaintext bits selected by mask
            parity_P = get_parity(P, MASK_P)
            
            # Undo final permutation to get L/R before IP^-1
            # After IP: we get state before final permutation
            pre_output = cipher.permute(C, cipher.IP_TABLE, 64)
            L_last = pre_output & 0xFFFFFFFF
            R_last = (pre_output >> 32) & 0xFFFFFFFF
            
            # Partially decrypt: compute S-box input for last round
            # Expand L_last (which becomes input to f in last round due to swap at end)
            expanded = cipher.permute(L_last, cipher.E_TABLE, 32)
            
            # Get 6-bit input to S-box
            shift = (7 - sbox_idx) * 6
            sbox_in_bits = (expanded >> shift) & 0x3F
            
            # XOR with key hypothesis
            sbox_in = sbox_in_bits ^ k_guess
            
            # Calculate S-box output
            row = ((sbox_in >> 5) & 1) * 2 + (sbox_in & 1)
            col = (sbox_in >> 1) & 0x0F
            sbox_out_val = cipher.S_BOXES[sbox_idx][row][col]
            
            # Parity of S-box output (using all 4 bits for maximum bias)
            parity_S_out = get_parity(sbox_out_val, 0x0F)
            
            # Linear approximation: P_parity XOR S_out_parity should equal key bit parity
            if (parity_P ^ parity_S_out) == 0:
                count_match += 1
        
        # Bias = deviation from 50%
        bias = abs(count_match - (n_pairs / 2))
        biases[k_guess] = bias
    
    # Step 4: Select best candidate
    best_k = biases.index(max(biases))
    
    # Extract true 6-bit key fragment for S-box from subkey
    # S5 gets bits 18-23 of 48-bit subkey (0-indexed from MSB)
    true_k_fragment = (target_subkey >> (48 - (sbox_idx + 1) * 6)) & 0x3F
    
    print(f"\n[4] Results:")
    print(f"    Best key candidate: {best_k:02x} (binary: {best_k:06b})")
    print(f"    True key fragment:  {true_k_fragment:02x} (binary: {true_k_fragment:06b})")
    print(f"    Bias: {max(biases):.2f} (expected ~N/2 = {n_pairs/2:.0f})")
    
    success = (best_k == true_k_fragment)
    if success:
        print("\n✓ ATTACK SUCCESSFUL!")
    else:
        print("\n✗ Attack failed - try increasing n_pairs or rounds")
    
    return best_k, true_k_fragment, success


if __name__ == "__main__":
    # Run attack with MILP-computed masks
    print("=" * 60)
    print("Running Linear Attack with MILP-optimized masks")
    print("=" * 60)
    linear_attack(rounds=3, n_pairs=20000, use_milp=True)
    
    print("\n" + "=" * 60)
    print("Running Linear Attack with fallback mask (comparison)")
    print("=" * 60)
    linear_attack(rounds=3, n_pairs=20000, use_milp=False)