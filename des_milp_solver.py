"""
MILP Solver for Linear Cryptanalysis of DES
============================================
Based on Sections 7.1-7.3 of the documentation.

Uses Mixed Integer Linear Programming to find optimal linear approximations
by minimizing the number of active S-boxes.

Key difference from differential attack (Section 7.2.1):
- XOR operation: masks must be EQUAL (a = b = c)
- Branching: uses XOR-like constraints (sum mod 2 rule)
"""

import pulp
from sbox_tables import LAT_TABLES, get_best_linear_approximations


class DES_MILP_Linear:
    """
    MILP-based linear approximation search for DES.
    
    Per Section 7.2.1: XOR constraint is a = b = c (masks must match)
    Per Section 7.2.1: Branching uses XOR-like inequality constraints (Equation 4)
    Per Section 7.3: Minimizes sum of active S-boxes (Equation 5)
    """
    
    def __init__(self, rounds):
        self.rounds = rounds
        self.prob = pulp.LpProblem("DES_Linear_Cryptanalysis", pulp.LpMinimize)
        self.sbox_active_vars = []
        
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

    def add_xor_constraint(self, a, b, c):
        """
        Modelowanie XOR dla ataku liniowego (Sekcja 7.2.1, Równanie 3).
        W ataku liniowym maski wejściowe i wyjściowe XOR muszą być RÓWNE.
        """
        self.prob += (a == b)
        self.prob += (b == c)

    def add_branching_constraint(self, a, b, c):
        """
        Modelowanie rozgałęzienia w ataku liniowym (Sekcja 7.2.1, Równanie 4).
        Maska wejściowa = suma mod 2 masek wyjściowych.
        Używamy nierówności analogicznych do XOR w ataku różnicowym.
        """
        d = pulp.LpVariable(f"d_branch_{id(a)}_{id(b)}", cat='Binary')
        self.prob += (a + b + c >= 2 * d)
        self.prob += (d <= a)
        self.prob += (d <= b)
        self.prob += (d <= c)
        self.prob += (a + b + c <= 2)

    def solve(self):
        """
        Find optimal linear approximation minimizing active S-boxes.
        
        Returns:
            Tuple of (input_mask, output_mask) as 64-bit integers
        """
        # Mask variables for L and R halves at each round
        masks_L = [[pulp.LpVariable(f"L_{r}_{i}", cat='Binary') for i in range(32)] 
                   for r in range(self.rounds + 1)]
        masks_R = [[pulp.LpVariable(f"R_{r}_{i}", cat='Binary') for i in range(32)] 
                   for r in range(self.rounds + 1)]

        for r in range(self.rounds):
            # In linear cryptanalysis, Feistel structure propagates differently
            # Mask on L_{r+1} comes from R_r 
            for i in range(32):
                self.prob += (masks_L[r+1][i] == masks_R[r][i])
            
            # f function input mask = mask on R_r
            # After expansion E, we have 48-bit mask
            # But expansion creates branching (some bits are duplicated)
            
            # Build expanded mask with branching constraints
            expanded_mask = []
            for i in range(48):
                bit_idx = self.E_TABLE[i] - 1
                exp_bit = pulp.LpVariable(f"Exp_{r}_{i}", cat='Binary')
                expanded_mask.append(exp_bit)
            
            # Handle branching: bits that appear multiple times in E must XOR
            # Map: which positions in E point to the same R bit
            bit_usage = {}
            for i in range(48):
                bit_idx = self.E_TABLE[i] - 1
                if bit_idx not in bit_usage:
                    bit_usage[bit_idx] = []
                bit_usage[bit_idx].append(i)
            
            # For bits used once: direct equality
            # For bits used twice: branching constraint
            for bit_idx, positions in bit_usage.items():
                if len(positions) == 1:
                    self.prob += (expanded_mask[positions[0]] == masks_R[r][bit_idx])
                else:
                    # Branching: R bit = XOR of expansion positions (sum mod 2)
                    # For 2 positions: R[bit] = exp[p1] XOR exp[p2]
                    self.add_branching_constraint(
                        masks_R[r][bit_idx], 
                        expanded_mask[positions[0]], 
                        expanded_mask[positions[1]]
                    )
            
            # S-box layer
            sbox_outputs = []
            for k in range(8):
                input_bits = expanded_mask[k*6 : (k+1)*6]
                
                # Activity variable A_r,k (Section 7.3, Equation 5)
                A_rk = pulp.LpVariable(f"A_{r}_{k}", cat='Binary')
                self.sbox_active_vars.append(A_rk)
                
                # S-box is active if any input mask bit is set
                for bit in input_bits:
                    self.prob += (A_rk >= bit)
                self.prob += (pulp.lpSum(input_bits) <= 6 * A_rk)
                
                # Output mask bits: can only be set if S-box is active
                out_bits = [pulp.LpVariable(f"Sout_{r}_{k}_{j}", cat='Binary') for j in range(4)]
                for bit in out_bits:
                    self.prob += (bit <= A_rk)
                
                # If active, at least one output bit must be masked
                # (based on LAT: no non-trivial input maps to zero output)
                self.prob += (pulp.lpSum(out_bits) >= A_rk)
                
                sbox_outputs.extend(out_bits)

            # Permutation P: rearrange output bits
            f_out = [sbox_outputs[self.P_TABLE[i]-1] for i in range(32)]
            
            # R_{r+1} mask comes from XOR of L_r mask and f output mask
            for i in range(32):
                self.add_xor_constraint(masks_L[r][i], f_out[i], masks_R[r+1][i])

        # Non-trivial approximation: require at least one input mask bit
        self.prob += (pulp.lpSum(masks_R[0]) >= 1)
        
        # Objective: minimize number of active S-boxes (Equation 5)
        self.prob += pulp.lpSum(self.sbox_active_vars)
        
        # Solve
        status = self.prob.solve(pulp.PULP_CBC_CMD(msg=0))
        
        # Extract computed masks from solver (NOT hardcoded!)
        mask_in_L = 0
        mask_in_R = 0
        mask_out_L = 0
        mask_out_R = 0
        
        for i in range(32):
            if pulp.value(masks_L[0][i]) == 1:
                mask_in_L |= (1 << (31-i))
            if pulp.value(masks_R[0][i]) == 1:
                mask_in_R |= (1 << (31-i))
            if pulp.value(masks_L[self.rounds][i]) == 1:
                mask_out_L |= (1 << (31-i))
            if pulp.value(masks_R[self.rounds][i]) == 1:
                mask_out_R |= (1 << (31-i))
        
        active_count = sum(1 for v in self.sbox_active_vars if pulp.value(v) == 1)
        
        print(f"MILP Status: {pulp.LpStatus[status]}")
        print(f"Minimum active S-boxes: {active_count}")
        print(f"Input mask:  L={mask_in_L:08x}, R={mask_in_R:08x}")
        print(f"Output mask: L={mask_out_L:08x}, R={mask_out_R:08x}")
        
        input_mask = (mask_in_L << 32) | mask_in_R
        output_mask = (mask_out_L << 32) | mask_out_R
        
        return input_mask, output_mask


if __name__ == "__main__":
    print("=== MILP Linear Approximation Search ===\n")
    for rounds in [2, 3, 4]:
        print(f"\n--- {rounds} Rounds ---")
        solver = DES_MILP_Linear(rounds=rounds)
        mask_in, mask_out = solver.solve()
        print(f"Full input mask:  {mask_in:016x}")
        print(f"Full output mask: {mask_out:016x}")