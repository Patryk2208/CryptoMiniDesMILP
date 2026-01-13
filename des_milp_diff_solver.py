"""
MILP Solver for Differential Cryptanalysis of DES
==================================================
Based on Sections 6.1-6.3 of the documentation.

Uses Mixed Integer Linear Programming to find optimal differential characteristics
by minimizing the number of active S-boxes.
"""

import pulp
from sbox_tables import DDT_TABLES, get_valid_differential_transitions


class DES_MILP_Differential:
    """
    MILP-based differential path search for DES.
    
    Per Section 6.2.1: XOR constraint modeled as a + b + c >= 2d, d <= a, d <= b, d <= c, a + b + c <= 2
    Per Section 6.3: Minimizes sum of active S-boxes (Equation 2)
    """
    
    def __init__(self, rounds):
        self.rounds = rounds
        self.prob = pulp.LpProblem("DES_Differential_Path_Search", pulp.LpMinimize)
        
        # DES Tables
        self.E_TABLE = [
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
        ]
        self.P_TABLE = [
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
        ]

    def add_xor_constraints(self, a, b, c):
        """
        Model XOR constraint for differential cryptanalysis (Section 6.2.1, Equation 1).
        
        For a ⊕ b = c in differential domain:
        The constraint ensures consistent difference propagation.
        """
        d = pulp.LpVariable(f"d_xor_{id(a)}_{id(b)}", cat='Binary')
        self.prob += (a + b + c >= 2 * d)
        self.prob += (d <= a)
        self.prob += (d <= b)
        self.prob += (d <= c)
        self.prob += (a + b + c <= 2)

    def solve(self):
        """
        Find optimal differential characteristic minimizing active S-boxes.
        
        Returns:
            64-bit input difference as integer
        """
        # Create variables for left (L) and right (R) halves at each round
        diff_L = [[pulp.LpVariable(f"L_{r}_{i}", cat='Binary') for i in range(32)] 
                  for r in range(self.rounds + 1)]
        diff_R = [[pulp.LpVariable(f"R_{r}_{i}", cat='Binary') for i in range(32)] 
                  for r in range(self.rounds + 1)]
        sbox_active_vars = []

        for r in range(self.rounds):
            # Feistel structure: L_{r+1} = R_r
            for i in range(32):
                self.prob += (diff_L[r+1][i] == diff_R[r][i])
            
            # Expansion E: 32 -> 48 bits (Section 1.3, Table 6)
            expanded_R = [diff_R[r][self.E_TABLE[i]-1] for i in range(48)]
            
            # S-box layer
            sbox_outputs = []
            for k in range(8):
                input_bits = expanded_R[k*6 : (k+1)*6]
                
                # Activity variable A_r,k (Section 6.3)
                A_rk = pulp.LpVariable(f"A_{r}_{k}", cat='Binary')
                sbox_active_vars.append(A_rk)
                
                # S-box is active if any input bit has difference
                # Using DDT: we know valid transitions exist only for active S-boxes
                for bit in input_bits:
                    self.prob += (A_rk >= bit)
                
                # Sum of input bits <= 6 * A_rk (if active, sum can be 1-6; if inactive, sum must be 0)
                self.prob += (pulp.lpSum(input_bits) <= 6 * A_rk)
                
                # Output bits: can only have differences if S-box is active
                out_bits = [pulp.LpVariable(f"Sout_{r}_{k}_{j}", cat='Binary') for j in range(4)]
                for bit in out_bits:
                    self.prob += (bit <= A_rk)
                
                # If S-box is active, at least one output bit should have difference
                # (based on DDT analysis: no active input maps to zero output except Δ=0→0)
                self.prob += (pulp.lpSum(out_bits) >= A_rk)
                
                sbox_outputs.extend(out_bits)

            # Permutation P (Section 1.3, Table 7)
            f_out = [sbox_outputs[self.P_TABLE[i]-1] for i in range(32)]
            
            # Feistel: R_{r+1} = L_r ⊕ f(R_r, K)
            for i in range(32):
                self.add_xor_constraints(diff_L[r][i], f_out[i], diff_R[r+1][i])

        # Non-trivial characteristic: require at least one bit difference in input R
        self.prob += (pulp.lpSum(diff_R[0]) >= 1)
        
        # Objective: minimize number of active S-boxes (Equation 2)
        self.prob += pulp.lpSum(sbox_active_vars)
        
        # Solve
        status = self.prob.solve(pulp.PULP_CBC_CMD(msg=0))
        
        # Extract input difference
        res_L = 0
        res_R = 0
        for i in range(32):
            if pulp.value(diff_L[0][i]) == 1: 
                res_L |= (1 << (31-i))
            if pulp.value(diff_R[0][i]) == 1: 
                res_R |= (1 << (31-i))
        
        # Count active S-boxes
        active_count = sum(1 for v in sbox_active_vars if pulp.value(v) == 1)
        print(f"MILP Status: {pulp.LpStatus[status]}")
        print(f"Minimum active S-boxes: {active_count}")
        print(f"Optimal input difference: L={res_L:08x}, R={res_R:08x}")
            
        return (res_L << 32) | res_R


if __name__ == "__main__":
    print("=== MILP Differential Path Search ===\n")
    for rounds in [3, 4, 5]:
        print(f"\n--- {rounds} Rounds ---")
        solver = DES_MILP_Differential(rounds=rounds)
        diff_in = solver.solve()
        print(f"Full input difference: {diff_in:016x}")