"""
Atak Kryptoanalizy Różnicowej na DES
=====================================
Na podstawie Sekcji 2 i 6 dokumentacji.

Wykorzystuje solver MILP do znajdowania optymalnych charakterystyk różnicowych,
a następnie przeprowadza atak metodą zliczania do odzyskania klucza ostatniej rundy.
"""

import random
from collections import Counter
# Importujemy implementację DES
from full_des import DES
# Importujemy solver MILP dla różnic
from des_milp_diff_solver import DES_MILP_Differential


class DifferentialAttack:
    """
    Klasa implementująca atak różnicowy na DES.
    
    Zgodnie z Sekcją 2.1: Atak polega na znajdowaniu charakterystyki różnicowej
    i wykorzystaniu jej do odzyskania fragmentów klucza poprzez analizę par
    tekstów o znanej różnicy.
    """
    
    def __init__(self, des_instance):
        self.cipher = des_instance
        # Tablica odwrotna do permutacji P (potrzebna do cofania permutacji w ataku)
        self.P_INV_TABLE = [0] * 32
        for idx, val in enumerate(self.cipher.P_TABLE):
            self.P_INV_TABLE[val - 1] = idx + 1

    def undo_ip(self, ciphertext):
        """
        Cofa permutację końcową IP-1.
        
        Zwraca:
            Krotkę (R_last, L_last) - stan przed permutacją końcową
        """
        pre_output = self.cipher.permute(ciphertext, self.cipher.IP_TABLE, 64)
        r_last = (pre_output >> 32) & 0xFFFFFFFF
        l_last = pre_output & 0xFFFFFFFF
        return r_last, l_last

    def get_sbox_output_diff(self, r_last, r_last_prime, key_chunk, sbox_idx):
        """
        Symuluje cofnięcie operacji w S-boxie dla danej hipotezy klucza.
        
        Zgodnie z Sekcją 6.4: Dla każdego kandydata na klucz wykonujemy
        częściowe odszyfrowanie i sprawdzamy zgodność różnic.
        
        Argumenty:
            r_last: Prawa połowa pierwszego szyfrogramu (L po IP)
            r_last_prime: Prawa połowa drugiego szyfrogramu
            key_chunk: 6-bitowa hipoteza klucza dla danego S-boxa
            sbox_idx: Indeks S-boxa (0-7)
        
        Zwraca:
            Różnicę wyjściową S-boxa dla podanej hipotezy klucza
        """
        # 1. Pobierz 6 bitów wchodzących do S-boxa (po ekspansji E)
        expanded_R = self.cipher.permute(r_last, self.cipher.E_TABLE, 32)
        expanded_R_prime = self.cipher.permute(r_last_prime, self.cipher.E_TABLE, 32)
        
        shift = (7 - sbox_idx) * 6
        block_input = (expanded_R >> shift) & 0x3F
        block_input_prime = (expanded_R_prime >> shift) & 0x3F
        
        # 2. XOR z hipotezą klucza
        in_sbox = block_input ^ key_chunk
        in_sbox_prime = block_input_prime ^ key_chunk
        
        # 3. Oblicz wyjście z S-boxa
        def sbox_val(bits, box_idx):
            row = ((bits >> 5) & 1) * 2 + (bits & 1)
            col = (bits >> 1) & 0x0F
            return self.cipher.S_BOXES[box_idx][row][col]

        out_val = sbox_val(in_sbox, sbox_idx)
        out_val_prime = sbox_val(in_sbox_prime, sbox_idx)
        
        return out_val ^ out_val_prime

    def run_attack(self, diff_in, rounds, num_pairs=1000):
        """
        Przeprowadza atak różnicowy metodą zliczania.
        
        Zgodnie z Sekcją 6.4 (Weryfikacja i odzyskiwanie klucza):
        1. Generowanie par tekstów o różnicy diff_in
        2. Dla każdego S-boxa testowanie wszystkich 64 hipotez klucza
        3. Wybór hipotezy o największej zgodności
        
        Argumenty:
            diff_in: 64-bitowa różnica wejściowa (z MILP)
            rounds: Liczba rund szyfru
            num_pairs: Liczba par do wygenerowania
        
        Zwraca:
            48-bitowy odzyskany klucz ostatniej rundy
        """
        print(f"[*] Generowanie {num_pairs} par tekstów dla różnicy: {diff_in:016x}...")
        
        pairs = []
        for _ in range(num_pairs):
            p1 = random.getrandbits(64)
            p2 = p1 ^ diff_in
            c1 = self.cipher.encrypt(p1)
            c2 = self.cipher.encrypt(p2)
            pairs.append((c1, c2))

        print("[*] Ekstrakcja klucza metodą zliczania...")
        recovered_key_fragments = [0] * 8
        
        print("[DEBUG] Wyznaczanie oczekiwanej różnicy wyjściowej z poprzedniej rundy...")
        
        # Pętla po wszystkich S-Boxach
        for sbox_idx in range(8):
            votes = Counter()
            
            # Pokaż postęp
            print(f"    -> Analiza S-Box {sbox_idx + 1}/8...") 

            for k_guess in range(64):
                diffs_for_guess = []
                
                # Iterujemy po wszystkich wygenerowanych parach
                for c1, c2 in pairs: 
                    r1, l1 = self.undo_ip(c1)
                    r2, l2 = self.undo_ip(c2)
                    
                    # Różnica wyjściowa S-boxa (przed P)
                    val = self.get_sbox_output_diff(l1, l2, k_guess, sbox_idx)
                    diffs_for_guess.append(val)
                
                # Szukamy najczęstszej różnicy dla tego kandydata na klucz
                most_common_diff, count = Counter(diffs_for_guess).most_common(1)[0]
                votes[k_guess] = count

            # Wybieramy klucz o najwyższym 'piku' (największej zgodności)
            best_k, count = votes.most_common(1)[0]
            recovered_key_fragments[sbox_idx] = best_k
            
            print(f"      Zwycięzca: {best_k:02x} (Trafienia: {count}/{num_pairs})")

        # Składamy 48-bitowy klucz z 8 fragmentów po 6 bitów
        round_key = 0
        for i in range(8):
            round_key = (round_key << 6) | recovered_key_fragments[i]
        return round_key


if __name__ == "__main__":
    # 1. Konfiguracja
    ROUNDS = 4
    SECRET_KEY = 0x133457799BBCDFF1
    des = DES(SECRET_KEY, rounds=ROUNDS)
    true_last_key = des.keys[ROUNDS-1]
    
    print(f"--- ATAK RÓŻNICOWY Z MILP ({ROUNDS} RUNDY) ---")
    
    # 2. Użycie solvera MILP
    milp_solver = DES_MILP_Differential(rounds=ROUNDS-1)  # Szukamy ścieżki do przedostatniej rundy
    optimal_diff_in = milp_solver.solve()
    
    # 3. Atak
    attacker = DifferentialAttack(des)
    found_key = attacker.run_attack(optimal_diff_in, ROUNDS, num_pairs=10000)
    
    print("\n--- WYNIK ---")
    print(f"Prawdziwy klucz ost. rundy: {true_last_key:012x}")
    print(f"Znaleziony klucz ost. rundy: {found_key:012x}")
    
    # Obliczanie zgodności bitów
    matches = bin(~(true_last_key ^ found_key) & 0xFFFFFFFFFFFF).count('1')
    print(f"Zgodność bitów: {matches}/48")