import pulp

class DES_MILP_Differential:
    def __init__(self, rounds):
        self.rounds = rounds
        self.prob = pulp.LpProblem("DES_Differential_Path_Search", pulp.LpMinimize)
        
        # Tabele permutacji
        self.E_TABLE = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
        self.P_TABLE = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    def add_xor_constraints(self, a, b, c):
        # POPRAWKA: Używamy ścisłej równości dla XOR (suma musi być 0 lub 2)
        d = pulp.LpVariable(f"d_xor_{id(a)}_{id(b)}", cat='Binary')
        self.prob += (a + b + c == 2 * d) 

    def solve(self):
        diff_L = [[pulp.LpVariable(f"L_{r}_{i}", cat='Binary') for i in range(32)] for r in range(self.rounds + 1)]
        diff_R = [[pulp.LpVariable(f"R_{r}_{i}", cat='Binary') for i in range(32)] for r in range(self.rounds + 1)]
        sbox_active_vars = []

        for r in range(self.rounds):
            # L_{r+1} = R_r
            for i in range(32):
                self.prob += (diff_L[r+1][i] == diff_R[r][i])
            
            # f function
            expanded_R = [diff_R[r][self.E_TABLE[i]-1] for i in range(48)]
            sbox_outputs = []
            
            for k in range(8):
                input_bits = expanded_R[k*6 : (k+1)*6]
                A_rk = pulp.LpVariable(f"A_{r}_{k}", cat='Binary')
                sbox_active_vars.append(A_rk)
                
                # Jeśli jakikolwiek bit wejściowy jest 1, S-box jest aktywny
                for bit in input_bits:
                    self.prob += (A_rk >= bit)
                
                # Wyjście z S-boxa (uproszczone: może być cokolwiek jeśli Active)
                out_bits = [pulp.LpVariable(f"Sout_{r}_{k}_{j}", cat='Binary') for j in range(4)]
                for bit in out_bits:
                    self.prob += (bit <= A_rk)
                sbox_outputs.extend(out_bits)

            f_out = [sbox_outputs[self.P_TABLE[i]-1] for i in range(32)]
            
            # R_{r+1} = L_r ^ f_out
            for i in range(32):
                self.add_xor_constraints(diff_L[r][i], f_out[i], diff_R[r+1][i])

        # POPRAWKA: Wymuś niezerową różnicę w PRAWEJ połowie (żeby runda 1 pracowała)
        self.prob += (pulp.lpSum(diff_R[0]) >= 1)
        
        self.prob += pulp.lpSum(sbox_active_vars)
        self.prob.solve(pulp.PULP_CBC_CMD(msg=0))
        
        res_L = 0
        res_R = 0
        for i in range(32):
            if pulp.value(diff_L[0][i]) == 1: res_L |= (1 << (31-i))
            if pulp.value(diff_R[0][i]) == 1: res_R |= (1 << (31-i))
            
        return (res_L << 32) | res_R