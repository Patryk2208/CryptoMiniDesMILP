import random
from full_des import DES

def get_parity(value, mask):
    masked = value & mask
    return bin(masked).count('1') % 2

def linear_attack_3rounds():
    # Zmieniamy na 20k par dla pewności
    N_PAIRS = 20000
    ROUNDS = 3
    SECRET_KEY = 0x133457799BBCDFF1 
    
    cipher = DES(SECRET_KEY, rounds=ROUNDS)
    target_subkey = cipher.keys[2] 
    
    # --- POPRAWKA: Silna Aproksymacja Matsui dla S5 ---
    # S5: Input bit 0x10 (czwarty bit) -> Output 0x0F (wszystkie 4 bity)
    # To daje duży bias. Maska plaintextu musi celować w bit powiązany z wyjściem S5 z poprzednich rund.
    # Używamy sprawdzonej maski dla 3-rundowego DES:
    MASK_P = 0x0000000000008000 # Bit celujący w S5
    
    print(f"--- ATAK LINIOWY (POPRAWIONY) ---")
    print(f"Szukany podklucz K3: {target_subkey:012x}")
    print(f"Zbieranie {N_PAIRS} par...")
    
    data_pairs = []
    for _ in range(N_PAIRS):
        p = random.getrandbits(64)
        c = cipher.encrypt(p)
        data_pairs.append((p, c))

    print("Analiza statystyczna...")
    biases = [0.0] * 64 
    
    for k_guess in range(64):
        count_match = 0
        for P, C in data_pairs:
            parity_P = get_parity(P, MASK_P)
            
            # Cofanie ostatniej rundy
            pre_output = cipher.permute(C, cipher.IP_TABLE, 64)
            L3 = pre_output & 0xFFFFFFFF
            # R3 = (pre_output >> 32) & 0xFFFFFFFF # Nieużywane w równaniu
            
            # Obliczanie wyjścia S5
            expanded_L3 = cipher.permute(L3, cipher.E_TABLE, 32)
            shift = (7 - 4) * 6 # S5 index = 4
            sbox_in_bits = (expanded_L3 >> shift) & 0x3F
            sbox_in = sbox_in_bits ^ k_guess
            
            row = ((sbox_in >> 5) & 1) * 2 + (sbox_in & 1)
            col = (sbox_in >> 1) & 0x0F
            sbox_out_val = cipher.S_BOXES[4][row][col]
            
            # POPRAWKA: Maska wyjściowa 0x0F (wszystkie bity S-boxa)
            # To znacznie zwiększa bias w porównaniu do sprawdzania 1 bitu
            parity_S_out = get_parity(sbox_out_val, 0x0F) 
            
            if (parity_P ^ parity_S_out) == 0:
                count_match += 1
        
        bias = abs(count_match - (N_PAIRS / 2))
        biases[k_guess] = bias

    best_k = biases.index(max(biases))
    
    # Weryfikacja
    true_k3_full = target_subkey
    true_k_s5 = (true_k3_full >> 18) & 0x3F
    
    print(f"\nNajlepszy kandydat: {best_k:02x} (bin: {best_k:06b})")
    print(f"Prawdziwy fragment: {true_k_s5:02x} (bin: {true_k_s5:06b})")
    print(f"Bias: {max(biases):.2f}")
    
    if best_k == true_k_s5:
        print("SUKCES: Atak udany!")
    else:
        print("BŁĄD: Zwiększ liczbę par.")

if __name__ == "__main__":
    linear_attack_3rounds()