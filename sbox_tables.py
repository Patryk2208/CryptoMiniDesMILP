"""
S-Box Tables Module for DES Cryptanalysis
==========================================
Implements DDT (Difference Distribution Table) and LAT (Linear Approximation Table)
as described in Sections 6.2.2 and 7.2.2 of the documentation.

References:
- DDT: Used in differential cryptanalysis to find valid differential transitions
- LAT: Used in linear cryptanalysis to find biased linear approximations
"""

from full_des import DES


def compute_ddt(sbox):
    """
    Compute Difference Distribution Table for a 6->4 bit S-box.
    
    DDT[Δin][Δout] = count of inputs x where S(x) ⊕ S(x ⊕ Δin) = Δout
    
    Per Section 6.2.2 (Eq. for DDT probability):
    P[ΔX → ΔY] = |{x : S(x) ⊕ S(x ⊕ ΔX) = ΔY}| / 2^n
    
    Args:
        sbox: List of 4 rows, each with 16 columns (standard DES S-box format)
    
    Returns:
        64x16 table where DDT[i][j] = count of transitions from input diff i to output diff j
    """
    ddt = [[0] * 16 for _ in range(64)]
    
    for x in range(64):
        # Convert 6-bit input to row/col format for S-box lookup
        row_x = ((x >> 5) & 1) * 2 + (x & 1)
        col_x = (x >> 1) & 0x0F
        sbox_x = sbox[row_x][col_x]
        
        for delta_in in range(64):
            x_prime = x ^ delta_in
            row_x_prime = ((x_prime >> 5) & 1) * 2 + (x_prime & 1)
            col_x_prime = (x_prime >> 1) & 0x0F
            sbox_x_prime = sbox[row_x_prime][col_x_prime]
            
            delta_out = sbox_x ^ sbox_x_prime
            ddt[delta_in][delta_out] += 1
    
    return ddt


def compute_lat(sbox):
    """
    Compute Linear Approximation Table for a 6->4 bit S-box.
    
    LAT[α][β] = |{x : α·x = β·S(x)}| - 2^(n-1)
    
    Per Section 7.2.2 (Linear attack LAT definition):
    The value represents the bias from 50% of the linear approximation.
    
    Args:
        sbox: List of 4 rows, each with 16 columns (standard DES S-box format)
    
    Returns:
        64x16 table where LAT[α][β] = bias count for input mask α and output mask β
    """
    lat = [[0] * 16 for _ in range(64)]
    
    for alpha in range(64):  # Input mask (6 bits)
        for beta in range(16):  # Output mask (4 bits)
            count = 0
            for x in range(64):
                # Calculate S-box output
                row = ((x >> 5) & 1) * 2 + (x & 1)
                col = (x >> 1) & 0x0F
                s_out = sbox[row][col]
                
                # Parity of (α · x) = XOR of bits where alpha has 1s
                parity_in = bin(alpha & x).count('1') % 2
                # Parity of (β · S(x))
                parity_out = bin(beta & s_out).count('1') % 2
                
                if parity_in == parity_out:
                    count += 1
            
            # LAT value = count - 32 (bias from 50%)
            lat[alpha][beta] = count - 32
    
    return lat


def get_valid_differential_transitions(ddt, min_probability=0):
    """
    Get all valid (non-zero probability) differential transitions from a DDT.
    
    Args:
        ddt: 64x16 Difference Distribution Table
        min_probability: Minimum count threshold (0 = all non-zero)
    
    Returns:
        List of tuples (delta_in, delta_out, count)
    """
    transitions = []
    for d_in in range(64):
        for d_out in range(16):
            if ddt[d_in][d_out] > min_probability:
                transitions.append((d_in, d_out, ddt[d_in][d_out]))
    return transitions


def get_best_linear_approximations(lat, min_bias=0):
    """
    Get the best (highest absolute bias) linear approximations from a LAT.
    
    Args:
        lat: 64x16 Linear Approximation Table
        min_bias: Minimum absolute bias threshold
    
    Returns:
        List of tuples (input_mask, output_mask, bias) sorted by |bias|
    """
    approximations = []
    for alpha in range(64):
        for beta in range(16):
            bias = lat[alpha][beta]
            if abs(bias) > min_bias:
                approximations.append((alpha, beta, bias))
    
    # Sort by absolute bias (descending)
    approximations.sort(key=lambda x: abs(x[2]), reverse=True)
    return approximations


def max_differential_probability(ddt):
    """
    Get maximum differential probability for an S-box (excluding trivial Δ=0→0).
    
    Returns:
        (delta_in, delta_out, probability) tuple for best non-trivial differential
    """
    best = (0, 0, 0)
    for d_in in range(1, 64):  # Skip 0 (trivial)
        for d_out in range(16):
            if ddt[d_in][d_out] > best[2]:
                best = (d_in, d_out, ddt[d_in][d_out])
    
    # Probability = count / 64 (since 64 possible inputs)
    prob = best[2] / 64.0
    return best[0], best[1], prob


def max_linear_bias(lat):
    """
    Get maximum linear bias for an S-box (excluding trivial α=0, β=0).
    
    Returns:
        (input_mask, output_mask, bias) tuple for best non-trivial approximation
    """
    best = (0, 0, 0)
    for alpha in range(1, 64):  # Skip 0
        for beta in range(1, 16):  # Skip 0
            if abs(lat[alpha][beta]) > abs(best[2]):
                best = (alpha, beta, lat[alpha][beta])
    
    return best


# Pre-compute tables for all 8 DES S-boxes
DDT_TABLES = [compute_ddt(sbox) for sbox in DES.S_BOXES]
LAT_TABLES = [compute_lat(sbox) for sbox in DES.S_BOXES]


if __name__ == "__main__":
    print("=== S-Box Analysis for DES Cryptanalysis ===\n")
    
    for i in range(8):
        d_in, d_out, prob = max_differential_probability(DDT_TABLES[i])
        a_in, a_out, bias = max_linear_bias(LAT_TABLES[i])
        
        print(f"S{i+1}:")
        print(f"  Best differential: Δin={d_in:02x} -> Δout={d_out:x}, prob={prob:.4f}")
        print(f"  Best linear approx: α={a_in:02x}, β={a_out:x}, bias={bias}/32 = {abs(bias)/32:.4f}")
        print()
