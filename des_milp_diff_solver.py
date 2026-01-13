"""
Solver MILP dla Kryptoanalizy Różnicowej DES
=============================================
Na podstawie Sekcji 6.1-6.3 dokumentacji.

Wykorzystuje Mieszane Programowanie Liniowe Całkowitoliczbowe do znajdowania optymalnych 
charakterystyk różnicowych poprzez minimalizację liczby aktywnych S-boxów.
"""

import pulp
from sbox_tables import DDT_TABLES, get_valid_differential_transitions


class DES_MILP_Differential:
    """
    Wyszukiwanie ścieżki różnicowej oparte na MILP dla DES.
    
    Zgodnie z Sekcją 6.2.1: Ograniczenie XOR modelowane jako a + b + c >= 2d, d <= a, d <= b, d <= c, a + b + c <= 2
    Zgodnie z Sekcją 6.3: Minimalizuje sumę aktywnych S-boxów (Równanie 2)
    """
    
    def __init__(self, rounds):
        self.rounds = rounds
        self.prob = pulp.LpProblem("DES_Differential_Path_Search", pulp.LpMinimize)
        
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

    def add_xor_constraints(self, a, b, c):
        """
        Modelowanie ograniczenia XOR dla kryptoanalizy różnicowej (Sekcja 6.2.1, Równanie 1).
        
        Dla a ⊕ b = c w domenie różnicowej:
        Ograniczenie zapewnia spójną propagację różnic.
        """
        d = pulp.LpVariable(f"d_xor_{id(a)}_{id(b)}", cat='Binary')
        self.prob += (a + b + c >= 2 * d)
        self.prob += (d <= a)
        self.prob += (d <= b)
        self.prob += (d <= c)
        self.prob += (a + b + c <= 2)

    def solve(self):
        """
        Znajduje optymalną charakterystykę różnicową minimalizując liczbę aktywnych S-boxów.
        
        Zwraca:
            64-bitową różnicę wejściową jako liczbę całkowitą
        """
        # Tworzenie zmiennych dla lewej (L) i prawej (R) połowy dla każdej rundy
        diff_L = [[pulp.LpVariable(f"L_{r}_{i}", cat='Binary') for i in range(32)] 
                  for r in range(self.rounds + 1)]
        diff_R = [[pulp.LpVariable(f"R_{r}_{i}", cat='Binary') for i in range(32)] 
                  for r in range(self.rounds + 1)]
        sbox_active_vars = []

        for r in range(self.rounds):
            # Struktura Feistela: L_{r+1} = R_r
            for i in range(32):
                self.prob += (diff_L[r+1][i] == diff_R[r][i])
            
            # Ekspansja E: 32 -> 48 bitów (Sekcja 1.3, Tabela 6)
            expanded_R = [diff_R[r][self.E_TABLE[i]-1] for i in range(48)]
            
            # Warstwa S-boxów
            sbox_outputs = []
            for k in range(8):
                input_bits = expanded_R[k*6 : (k+1)*6]
                
                # Zmienna aktywności A_r,k (Sekcja 6.3)
                A_rk = pulp.LpVariable(f"A_{r}_{k}", cat='Binary')
                sbox_active_vars.append(A_rk)
                
                # S-box jest aktywny jeśli którykolwiek bit wejściowy ma różnicę
                # Wykorzystując DDT: wiemy, że poprawne przejścia istnieją tylko dla aktywnych S-boxów
                for bit in input_bits:
                    self.prob += (A_rk >= bit)
                
                # Suma bitów wejściowych <= 6 * A_rk (jeśli aktywny, suma może być 1-6; jeśli nieaktywny, musi być 0)
                self.prob += (pulp.lpSum(input_bits) <= 6 * A_rk)
                
                # Bity wyjściowe: mogą mieć różnice tylko jeśli S-box jest aktywny
                out_bits = [pulp.LpVariable(f"Sout_{r}_{k}_{j}", cat='Binary') for j in range(4)]
                for bit in out_bits:
                    self.prob += (bit <= A_rk)
                
                # Jeśli S-box jest aktywny, co najmniej jeden bit wyjściowy powinien mieć różnicę
                # (na podstawie analizy DDT: żadne aktywne wejście nie mapuje się na zerowe wyjście oprócz Δ=0→0)
                self.prob += (pulp.lpSum(out_bits) >= A_rk)
                
                sbox_outputs.extend(out_bits)

            # Permutacja P (Sekcja 1.3, Tabela 7)
            f_out = [sbox_outputs[self.P_TABLE[i]-1] for i in range(32)]
            
            # Feistel: R_{r+1} = L_r ⊕ f(R_r, K)
            for i in range(32):
                self.add_xor_constraints(diff_L[r][i], f_out[i], diff_R[r+1][i])

        # Nietrywialna charakterystyka: wymaga co najmniej jednego bitu różnicy w wejściowym R
        self.prob += (pulp.lpSum(diff_R[0]) >= 1)
        
        # Funkcja celu: minimalizuj liczbę aktywnych S-boxów (Równanie 2)
        self.prob += pulp.lpSum(sbox_active_vars)
        
        # Rozwiązanie
        status = self.prob.solve(pulp.PULP_CBC_CMD(msg=0))
        
        # Ekstrakcja różnicy wejściowej
        res_L = 0
        res_R = 0
        for i in range(32):
            if pulp.value(diff_L[0][i]) == 1: 
                res_L |= (1 << (31-i))
            if pulp.value(diff_R[0][i]) == 1: 
                res_R |= (1 << (31-i))
        
        # Zliczanie aktywnych S-boxów
        active_count = sum(1 for v in sbox_active_vars if pulp.value(v) == 1)
        print(f"Status MILP: {pulp.LpStatus[status]}")
        print(f"Minimalna liczba aktywnych S-boxów: {active_count}")
        print(f"Optymalna różnica wejściowa: L={res_L:08x}, R={res_R:08x}")
            
        return (res_L << 32) | res_R


if __name__ == "__main__":
    print("=== Wyszukiwanie Ścieżki Różnicowej MILP ===\n")
    for rounds in [3, 4, 5]:
        print(f"\n--- {rounds} Rundy ---")
        solver = DES_MILP_Differential(rounds=rounds)
        diff_in = solver.solve()
        print(f"Pełna różnica wejściowa: {diff_in:016x}")