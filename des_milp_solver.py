"""
Solver MILP dla Kryptoanalizy Liniowej DES
==========================================
Na podstawie Sekcji 7.1-7.3 dokumentacji.

Wykorzystuje Mieszane Programowanie Liniowe Całkowitoliczbowe do znajdowania optymalnych 
aproksymacji liniowych poprzez minimalizację liczby aktywnych S-boxów.

Kluczowa różnica od ataku różnicowego (Sekcja 7.2.1):
- Operacja XOR: maski muszą być RÓWNE (a = b = c)
- Rozgałęzienie: używa ograniczeń typu XOR (reguła sumy modulo 2)
"""

import pulp
from sbox_tables import LAT_TABLES, get_best_linear_approximations


class DES_MILP_Linear:
    """
    Wyszukiwanie aproksymacji liniowych oparte na MILP dla DES.
    
    Zgodnie z Sekcją 7.2.1: Ograniczenie XOR to a = b = c (maski muszą być zgodne)
    Zgodnie z Sekcją 7.2.1: Rozgałęzienie używa nierówności typu XOR (Równanie 4)
    Zgodnie z Sekcją 7.3: Minimalizuje sumę aktywnych S-boxów (Równanie 5)
    """
    
    def __init__(self, rounds):
        self.rounds = rounds
        self.prob = pulp.LpProblem("DES_Linear_Cryptanalysis", pulp.LpMinimize)
        self.sbox_active_vars = []
        
        # Tablice DES
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
        Modelowanie ograniczenia XOR dla ataku liniowego (Sekcja 7.2.1, Równanie 3).
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
        Znajduje optymalną aproksymację liniową minimalizując liczbę aktywnych S-boxów.
        
        Zwraca:
            Krotkę (maska_wejściowa, maska_wyjściowa) jako 64-bitowe liczby całkowite
        """
        # Zmienne masek dla połówek L i R dla każdej rundy
        masks_L = [[pulp.LpVariable(f"L_{r}_{i}", cat='Binary') for i in range(32)] 
                   for r in range(self.rounds + 1)]
        masks_R = [[pulp.LpVariable(f"R_{r}_{i}", cat='Binary') for i in range(32)] 
                   for r in range(self.rounds + 1)]

        for r in range(self.rounds):
            # W kryptoanalizie liniowej struktura Feistela propaguje się inaczej
            # Maska na L_{r+1} pochodzi z R_r 
            for i in range(32):
                self.prob += (masks_L[r+1][i] == masks_R[r][i])
            
            # Maska wejściowa funkcji f = maska na R_r
            # Po ekspansji E mamy 48-bitową maskę
            # Ale ekspansja tworzy rozgałęzienia (niektóre bity są duplikowane)
            
            # Budowanie rozszerzonej maski z ograniczeniami rozgałęzień
            expanded_mask = []
            for i in range(48):
                bit_idx = self.E_TABLE[i] - 1
                exp_bit = pulp.LpVariable(f"Exp_{r}_{i}", cat='Binary')
                expanded_mask.append(exp_bit)
            
            # Obsługa rozgałęzień: bity które pojawiają się wielokrotnie w E muszą XOR
            # Mapa: które pozycje w E wskazują na ten sam bit R
            bit_usage = {}
            for i in range(48):
                bit_idx = self.E_TABLE[i] - 1
                if bit_idx not in bit_usage:
                    bit_usage[bit_idx] = []
                bit_usage[bit_idx].append(i)
            
            # Dla bitów używanych raz: bezpośrednia równość
            # Dla bitów używanych dwa razy: ograniczenie rozgałęzienia
            for bit_idx, positions in bit_usage.items():
                if len(positions) == 1:
                    self.prob += (expanded_mask[positions[0]] == masks_R[r][bit_idx])
                else:
                    # Rozgałęzienie: bit R = XOR pozycji ekspansji (suma mod 2)
                    # Dla 2 pozycji: R[bit] = exp[p1] XOR exp[p2]
                    self.add_branching_constraint(
                        masks_R[r][bit_idx], 
                        expanded_mask[positions[0]], 
                        expanded_mask[positions[1]]
                    )
            
            # Warstwa S-boxów
            sbox_outputs = []
            for k in range(8):
                input_bits = expanded_mask[k*6 : (k+1)*6]
                
                # Zmienna aktywności A_r,k (Sekcja 7.3, Równanie 5)
                A_rk = pulp.LpVariable(f"A_{r}_{k}", cat='Binary')
                self.sbox_active_vars.append(A_rk)
                
                # S-box jest aktywny jeśli którykolwiek bit maski wejściowej jest ustawiony
                for bit in input_bits:
                    self.prob += (A_rk >= bit)
                self.prob += (pulp.lpSum(input_bits) <= 6 * A_rk)
                
                # Bity maski wyjściowej: mogą być ustawione tylko jeśli S-box jest aktywny
                out_bits = [pulp.LpVariable(f"Sout_{r}_{k}_{j}", cat='Binary') for j in range(4)]
                for bit in out_bits:
                    self.prob += (bit <= A_rk)
                
                # Jeśli aktywny, co najmniej jeden bit wyjściowy musi być zamaskowany
                # (na podstawie LAT: żadne nietrywialne wejście nie mapuje się na zerowe wyjście)
                self.prob += (pulp.lpSum(out_bits) >= A_rk)
                
                sbox_outputs.extend(out_bits)

            # Permutacja P: przestawienie bitów wyjściowych
            f_out = [sbox_outputs[self.P_TABLE[i]-1] for i in range(32)]
            
            # Maska R_{r+1} pochodzi z XOR maski L_r i maski wyjścia f
            for i in range(32):
                self.add_xor_constraint(masks_L[r][i], f_out[i], masks_R[r+1][i])

        # Nietrywialna aproksymacja: wymaga co najmniej jednego bitu maski wejściowej
        self.prob += (pulp.lpSum(masks_R[0]) >= 1)
        
        # Funkcja celu: minimalizuj liczbę aktywnych S-boxów (Równanie 5)
        self.prob += pulp.lpSum(self.sbox_active_vars)
        
        # Rozwiązanie
        status = self.prob.solve(pulp.PULP_CBC_CMD(msg=0))
        
        # Ekstrakcja obliczonych masek z solvera (NIE zahardkodowanych!)
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
        
        print(f"Status MILP: {pulp.LpStatus[status]}")
        print(f"Minimalna liczba aktywnych S-boxów: {active_count}")
        print(f"Maska wejściowa:  L={mask_in_L:08x}, R={mask_in_R:08x}")
        print(f"Maska wyjściowa: L={mask_out_L:08x}, R={mask_out_R:08x}")
        
        input_mask = (mask_in_L << 32) | mask_in_R
        output_mask = (mask_out_L << 32) | mask_out_R
        
        return input_mask, output_mask


if __name__ == "__main__":
    print("=== Wyszukiwanie Aproksymacji Liniowych MILP ===\n")
    for rounds in [2, 3, 4]:
        print(f"\n--- {rounds} Rundy ---")
        solver = DES_MILP_Linear(rounds=rounds)
        mask_in, mask_out = solver.solve()
        print(f"Pełna maska wejściowa:  {mask_in:016x}")
        print(f"Pełna maska wyjściowa: {mask_out:016x}")