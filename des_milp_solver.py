import pulp
from full_des import DES
import sbox_tables

class DES_MILP_Linear:
    def __init__(self, rounds):
        self.rounds = rounds
        self.prob = pulp.LpProblem("DES_Linear_Cryptanalysis", pulp.LpMinimize)
        self.dummy_counter = 0

    def get_var_name(self, prefix, round_idx, bit_idx):
        return f"{prefix}_{round_idx}_{bit_idx}"

    def branch_constraints(self, input_vars, output1_vars, output2_vars):
        """
        Model Branching: input splits into out1 and out2.
        Linear Mask Constraint: input_mask = out1_mask ^ out2_mask
        
        This is modeled exactly like XOR in differential cryptanalysis (a = b ^ c)
        a + b + c <= 2
        a + b - c >= 0
        a - b + c >= 0
        -a + b + c >= 0
        """
        for i in range(len(input_vars)):
            a, b, c = input_vars[i], output1_vars[i], output2_vars[i]
            self.prob += a + b + c <= 2
            self.prob += a + b - c >= 0
            self.prob += a - b + c >= 0
            self.prob += -a + b + c >= 0

    def add_sbox_constraints(self, sbox_idx, input_vars, output_vars, active_var):
        """
        Crucial: Model valid LAT transitions.
        We select exactly ONE entry from the LAT table for this Round/Sbox if active_var=1.
        If active_var=0, then input and output masks must be 0.
        """
        # Get valid transitions (bias != 0)
        lat = sbox_tables.LAT_TABLES[sbox_idx]
        valid_transitions = [] # (alpha, beta)
        
        # We need to consider all possible non-zero bias transitions
        for alpha in range(64):
            for beta in range(16):
                bias = lat[alpha][beta]
                if alpha == 0 and beta == 0:
                    continue # Handled by active_var=0 case
                    
                if bias != 0:
                    valid_transitions.append((alpha, beta))
        
        # Create binary variables for each valid transition
        transition_vars = []
        for i, (alpha, beta) in enumerate(valid_transitions):
            t_var = pulp.LpVariable(f"T_{self.dummy_counter}_{sbox_idx}_{i}", cat='Binary')
            transition_vars.append((t_var, alpha, beta))
        self.dummy_counter += 1
        
        # Constraint: Sum of chosen transitions equals active_var
        self.prob += pulp.lpSum([t for t, _, _ in transition_vars]) == active_var
        
        # Link Input Mask bits to chosen alpha
        for bit in range(6):
            # Sum of T_k where alpha has bit 'bit' set. Note: alpha is integer.
            # bit 0 is LSB? standard DES usually big-endian but let's check input_vars order.
            # Assuming input_vars[0] is MSB (bit 1 of 6).
            # alpha integers: usually bit 0 is LSB.
            # So input_vars[0] corresponds to bit 5 of alpha?
            # Let's assume standard big-endian for vectors: index 0 is MSB.
            relevant_vars = [t for t, alpha, _ in transition_vars if (alpha >> (5-bit)) & 1]
            self.prob += input_vars[bit] == pulp.lpSum(relevant_vars)
            
        # Link Output Mask bits to chosen beta
        for bit in range(4):
            # Sum of T_k where beta has bit 'bit' set
            # Assuming output_vars[0] is MSB (bit 3 of beta).
            relevant_vars = [t for t, _, beta in transition_vars if (beta >> (3-bit)) & 1]
            self.prob += output_vars[bit] == pulp.lpSum(relevant_vars)

    def solve(self):
        # 32-bit masks for L and R for each round
        # +1 for final state
        L = [[pulp.LpVariable(self.get_var_name("L", r, bit), cat='Binary') for bit in range(32)] for r in range(self.rounds + 1)]
        R = [[pulp.LpVariable(self.get_var_name("R", r, bit), cat='Binary') for bit in range(32)] for r in range(self.rounds + 1)]
        
        all_active_sboxes = []
        
        for r in range(self.rounds):
            # Round r:
            # L[r], R[r] are inputs.
            # L[r+1] = R[r] (simple equality) in terms of value, but MASKS?
            # Value flow:
            # L_next = R_prev
            # R_next = L_prev ^ f(R_prev)
            
            # Linear Mask Propagation (Matsui):
            # Let Mask(L_r), Mask(R_r) be input masks.
            # Let Mask(L_{r+1}), Mask(R_{r+1}) be output masks.
            
            # Relation 1 (Branching at R_prev):
            # R_prev goes to L_next AND f_in.
            # Mask(R_prev) = Mask(L_next) ^ Mask(f_in)
            
            # Relation 2 (XOR at R_next):
            # R_next = L_prev ^ f_out
            # Mask(R_next) = Mask(L_prev) = Mask(f_out)
            
            # 1. Relation 2 Implementation:
            # Mask(f_out) = Mask(P_out)
            p_outputs = [pulp.LpVariable(self.get_var_name(f"p_out_{r}", 0, i), cat='Binary') for i in range(32)]
            
            for i in range(32):
                # Mask(L[r]) == Mask(R[r+1])
                self.prob += L[r][i] == R[r+1][i]
                # Mask(L[r]) == Mask(p_outputs)
                self.prob += L[r][i] == p_outputs[i]
                
            # 2. Relation 1 Implementation:
            # We need Mask(f_in) which enters Expansion.
            mask_f_in = [pulp.LpVariable(self.get_var_name(f"f_in_{r}", 0, i), cat='Binary') for i in range(32)]
            
            for i in range(32):
                # Branch: Mask(R[r]) = Mask(L[r+1]) ^ Mask(f_in)
                self.branch_constraints([R[r][i]], [L[r+1][i]], [mask_f_in[i]])

            # 3. Expansion E and S-boxes and P
            # Chain: mask_f_in --E--> sbox_inputs --S--> sbox_outputs --P--> p_outputs
            
            # Expansion (Branching of masks again, because E expands bits)
            sbox_inputs = [pulp.LpVariable(self.get_var_name(f"sb_in_{r}", 0, i), cat='Binary') for i in range(48)]
            
            bit_occurrences = {j: [] for j in range(1, 33)}
            for idx, val in enumerate(DES.E_TABLE):
                bit_occurrences[val].append(idx)
                
            for bit_val in range(1, 33):
                indices = bit_occurrences[bit_val]
                f_in_idx = bit_val - 1
                if len(indices) == 1:
                    self.prob += mask_f_in[f_in_idx] == sbox_inputs[indices[0]]
                elif len(indices) == 2:
                    # Branching: Mask(f_in bit) = Mask(sbox_in 1) ^ Mask(sbox_in 2)
                    self.branch_constraints([mask_f_in[f_in_idx]], [sbox_inputs[indices[0]]], [sbox_inputs[indices[1]]])

            # S-Boxes
            sbox_outputs = [pulp.LpVariable(self.get_var_name(f"sb_out_{r}", 0, i), cat='Binary') for i in range(32)]
            
            for i in range(8):
                sb_in = sbox_inputs[i*6 : (i+1)*6]
                sb_out = sbox_outputs[i*4 : (i+1)*4]
                
                active = pulp.LpVariable(f"A_{r}_{i}", cat='Binary')
                all_active_sboxes.append(active)
                
                self.add_sbox_constraints(i, sb_in, sb_out, active)
                
            # Permutation P
            # Map sbox_outputs to p_outputs via P
            # p_output[k] corresponds to bit coming FROM P_TABLE[k]
            # Since it's a wire, masks are equal.
            # p_outputs[k] = sbox_outputs[P_TABLE[k]-1]
            for i in range(32):
                src_idx = DES.P_TABLE[i] - 1
                self.prob += p_outputs[i] == sbox_outputs[src_idx]

        # --- New Constraint: Limit Active S-boxes in Attack Round (Round 3) ---
        # The attack requires guessing keys for S-boxes active in P_inv(L[n]).
        # L[n] is the mask that propagates to the next round's f-function.
        # We want to minimize the number of active S-boxes in that virtual next round.
        
        # We need P_inv mapping.
        # P_TABLE maps Input -> Output. Output[i] = Input[P[i]-1].
        # We want bits of Input (S-box output mask) given Output (L[n]).
        # Input[k] corresponds to Output[i] where P[i]-1 = k.
        # So mask for S-box output bit k is variable L[n][i] where P[i]-1 == k.
        
        r3_actives = []
        for sbox_idx in range(8):
            # Bits for S-box sbox_idx (4 bits: 4*sbox_idx ... 4*sbox_idx+3)
            # These are "Input" bits to P.
            # We find corresponding Output bits in L[self.rounds].
            
            sbox_active_vars = []
            for bit_offset in range(4):
                k = 4 * sbox_idx + bit_offset # 0..31
                # Find i such that P[i]-1 == k
                # P_TABLE is small, linear scan is fine.
                p_out_idx = -1
                for idx, val in enumerate(DES.P_TABLE):
                    if val - 1 == k:
                        p_out_idx = idx
                        break
                
                if p_out_idx != -1:
                    # L[self.rounds][p_out_idx] is the mask bit
                    sbox_active_vars.append(L[self.rounds][p_out_idx])
            
            # Create binary variable for R3 S-box activity
            r3_act = pulp.LpVariable(f"R3_Active_{sbox_idx}", cat='Binary')
            r3_actives.append(r3_act)
            
            # Constraint: If any bit is set, r3_act must be 1.
            # Sum(bits) <= 4 * r3_act  (If sum > 0, act must be 1. If sum=0, act can be 0)
            self.prob += pulp.lpSum(sbox_active_vars) <= 4 * r3_act
            
            # Also force r3_act to be 0 if sum is 0?
            # Not strictly necessary if we constrain sum(r3_actives) <= limit.
            # The solver will set r3_act=0 to satisfy limit if possible.
            
        # Limit total active S-boxes in Round 3
        # Start strictly with 1. If infeasible, increase.
        # But this is inside code. Let's try <= 1.
        self.prob += pulp.lpSum(r3_actives) <= 1

        # Objective: Minimize active S-boxes
        self.prob += pulp.lpSum(all_active_sboxes)
        
        # Constraint: At least one S-box must be active
        self.prob += pulp.lpSum(all_active_sboxes) >= 1
        
        status = self.prob.solve(pulp.PULP_CBC_CMD(msg=0))
        
        if status == pulp.LpStatusOptimal:
            print("MILP Status: Optimal")
            return self.extract_solution(L, R, all_active_sboxes)
        else:
            print("MILP Status:", pulp.LpStatus[status])
            return None

    def extract_solution(self, L, R, actives):
        res = {
            'input_mask_L': 0, 'input_mask_R': 0,
            'output_mask_L': 0, 'output_mask_R': 0,
            'active_sboxes': []
        }
        
        # Input Masks (Round 0)
        for i in range(32):
            if pulp.value(L[0][i]) > 0.5: res['input_mask_L'] |= (1 << (31-i))
            if pulp.value(R[0][i]) > 0.5: res['input_mask_R'] |= (1 << (31-i))
            
        # Output Masks (Round N)
        n = self.rounds
        for i in range(32):
            if pulp.value(L[n][i]) > 0.5: res['output_mask_L'] |= (1 << (31-i))
            if pulp.value(R[n][i]) > 0.5: res['output_mask_R'] |= (1 << (31-i))

        print(f"Active S-boxes count: {pulp.value(self.prob.objective)}")
        return res

if __name__ == "__main__":
    # Solve for 2 rounds
    solver = DES_MILP_Linear(rounds=2)
    result = solver.solve()
    
    if result:
        print(f"Input Mask: L={hex(result['input_mask_L'])}, R={hex(result['input_mask_R'])}")
        print(f"Output Mask: L={hex(result['output_mask_L'])}, R={hex(result['output_mask_R'])}")
