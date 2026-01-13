"""
Atak Kryptoanalizy Liniowej na DES
===================================
Na podstawie Sekcji 3 i 7 dokumentacji.

Wykorzystuje solver MILP do znajdowania optymalnych aproksymacji liniowych,
a następnie przeprowadza atak statystyczny do odzyskania fragmentów klucza.
"""

import random
from full_des import DES
from des_milp_solver import DES_MILP_Linear


def get_parity(value, mask):
    """Oblicza parzystość (XOR) bitów wybranych przez maskę."""
    masked = value & mask
    return bin(masked).count('1') % 2


def linear_attack(rounds=3, n_pairs=20000, secret_key=0x133457799BBCDFF1, use_milp=True):
    """
    Przeprowadza atak kryptoanalizy liniowej na DES.
    
    Argumenty:
        rounds: Liczba rund DES (domyślnie 3 dla demonstracji)
        n_pairs: Liczba par tekst jawny-szyfrogram do zebrania
        secret_key: Tajny klucz do zaatakowania
        use_milp: Czy używać solvera MILP dla optymalnej maski (True) czy maski zapasowej (False)
    
    Zwraca:
        Krotkę (najlepszy_kandydat_klucza, prawdziwy_fragment_klucza, sukces)
    """
    cipher = DES(secret_key, rounds=rounds)
    target_subkey = cipher.keys[rounds - 1]
    
    print(f"=== ATAK LINIOWY ({rounds} rundy) ===")
    print(f"Szukany podklucz K{rounds}: {target_subkey:012x}")
    
    # Krok 1: Użyj MILP do znalezienia optymalnej aproksymacji liniowej
    if use_milp:
        print("\n[1] Używam MILP do znalezienia optymalnej aproksymacji liniowej...")
        milp_solver = DES_MILP_Linear(rounds=rounds - 1)  # Atakujemy n-1 rund
        mask_in, mask_out = milp_solver.solve()
        
        # Ekstrakcja maski dla tekstu jawnego (wejście do szyfru)
        MASK_P = mask_in
        MASK_OUT_L = (mask_out >> 32) & 0xFFFFFFFF
        MASK_OUT_R = mask_out & 0xFFFFFFFF
    else:
        # Zapasowa: Użyj znanej dobrej aproksymacji dla S5 (atak Matsui)
        print("\n[1] Używam znanej dobrej maski (aproksymacja S5)...")
        MASK_P = 0x0000000000008000  # Celuje w S5
        MASK_OUT_L = 0x00008000
        MASK_OUT_R = 0x00000000
    
    print(f"    Maska wejściowa (tekst jawny):  {MASK_P:016x}")
    print(f"    Maska wyjściowa: L={MASK_OUT_L:08x}, R={MASK_OUT_R:08x}")
    
    # Określenie którego S-boxa atakować na podstawie maski
    # Na razie atakujemy S5 (indeks 4) ponieważ ma najlepszy bias wg analizy sbox_tables
    sbox_idx = 4
    print(f"    Atakowany S-box: S{sbox_idx + 1}")
    
    # Krok 2: Zbieranie par tekst jawny-szyfrogram
    print(f"\n[2] Zbieranie {n_pairs} par tekst jawny-szyfrogram...")
    data_pairs = []
    for _ in range(n_pairs):
        p = random.getrandbits(64)
        c = cipher.encrypt(p)
        data_pairs.append((p, c))
    
    # Krok 3: Analiza statystyczna - testowanie wszystkich 64 możliwych 6-bitowych fragmentów klucza
    print("\n[3] Przeprowadzanie analizy statystycznej...")
    biases = [0.0] * 64
    
    for k_guess in range(64):
        count_match = 0
        
        for P, C in data_pairs:
            # Parzystość bitów tekstu jawnego wybranych przez maskę
            parity_P = get_parity(P, MASK_P)
            
            # Cofnięcie permutacji końcowej aby uzyskać L/R przed IP^-1
            # Po IP: otrzymujemy stan przed permutacją końcową
            pre_output = cipher.permute(C, cipher.IP_TABLE, 64)
            L_last = pre_output & 0xFFFFFFFF
            R_last = (pre_output >> 32) & 0xFFFFFFFF
            
            # Częściowe odszyfrowanie: obliczenie wejścia S-boxa dla ostatniej rundy
            # Ekspansja L_last (która staje się wejściem do f w ostatniej rundzie przez zamianę na końcu)
            expanded = cipher.permute(L_last, cipher.E_TABLE, 32)
            
            # Pobranie 6-bitowego wejścia do S-boxa
            shift = (7 - sbox_idx) * 6
            sbox_in_bits = (expanded >> shift) & 0x3F
            
            # XOR z hipotezą klucza
            sbox_in = sbox_in_bits ^ k_guess
            
            # Obliczenie wyjścia S-boxa
            row = ((sbox_in >> 5) & 1) * 2 + (sbox_in & 1)
            col = (sbox_in >> 1) & 0x0F
            sbox_out_val = cipher.S_BOXES[sbox_idx][row][col]
            
            # Parzystość wyjścia S-boxa (używając wszystkich 4 bitów dla maksymalnego biasu)
            parity_S_out = get_parity(sbox_out_val, 0x0F)
            
            # Aproksymacja liniowa: parzystość_P XOR parzystość_S_out powinna równać się parzystości bitu klucza
            if (parity_P ^ parity_S_out) == 0:
                count_match += 1
        
        # Bias = odchylenie od 50%
        bias = abs(count_match - (n_pairs / 2))
        biases[k_guess] = bias
    
    # Krok 4: Wybór najlepszego kandydata
    best_k = biases.index(max(biases))
    
    # Ekstrakcja prawdziwego 6-bitowego fragmentu klucza dla S-boxa z podklucza
    # S5 otrzymuje bity 18-23 z 48-bitowego podklucza (indeksowane od 0 od MSB)
    true_k_fragment = (target_subkey >> (48 - (sbox_idx + 1) * 6)) & 0x3F
    
    print(f"\n[4] Wyniki:")
    print(f"    Najlepszy kandydat na klucz: {best_k:02x} (binarnie: {best_k:06b})")
    print(f"    Prawdziwy fragment klucza:  {true_k_fragment:02x} (binarnie: {true_k_fragment:06b})")
    print(f"    Bias: {max(biases):.2f} (oczekiwany ~N/2 = {n_pairs/2:.0f})")
    
    success = (best_k == true_k_fragment)
    if success:
        print("\n✓ ATAK ZAKOŃCZONY SUKCESEM!")
    else:
        print("\n✗ Atak nieudany - spróbuj zwiększyć n_pairs lub liczbę rund")
    
    return best_k, true_k_fragment, success


if __name__ == "__main__":
    # Uruchom atak z maskami obliczonymi przez MILP
    print("=" * 60)
    print("Uruchamianie Ataku Liniowego z maskami zoptymalizowanymi przez MILP")
    print("=" * 60)
    linear_attack(rounds=3, n_pairs=20000, use_milp=True)
    
    print("\n" + "=" * 60)
    print("Uruchamianie Ataku Liniowego z maską zapasową (porównanie)")
    print("=" * 60)
    linear_attack(rounds=3, n_pairs=20000, use_milp=False)