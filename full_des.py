class DES:
    def __init__(self, key_int, rounds=6):
        """
        Inicjalizacja DES.
        :param key_int: Klucz jako 64-bitowa liczba całkowita.
        :param rounds: Liczba rund (standardowo 16, dla projektu np. 6).
        """
        self.rounds = rounds
        if self.rounds > 16:
            raise ValueError("Standard DES ma maksymalnie 16 rund.")
        
        self.keys = self.generate_keys(key_int)

    # --- TABELE (Zdefiniowane zgodnie z plikiem krypto.pdf) ---
    
    # Tabela 4: Permutacja Początkowa IP [cite: 42]
    IP_TABLE = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Tabela 5: Permutacja Końcowa IP-1 [cite: 46]
    FP_TABLE = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]

    # Tabela 6: Permutacja z Rozszerzeniem E [cite: 50]
    E_TABLE = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]

    # Tabela 7: Permutacja P-bloku [cite: 56]
    P_TABLE = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]

    # Tabela 1: Permutacja Wejściowa Klucza (PC-1) [cite: 29]
    PC1_TABLE = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 28, 20, 12, 4,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
        61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ]

    # Tabela 3: Permutacja Kompresji (PC-2) [cite: 36]
    PC2_TABLE = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]

    # Tabela 2: Przesunięcie Połówek (Shifts) [cite: 32]
    SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # Tabela 8: Wartości S-bloków 
    S_BOXES = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    # --- METODY POMOCNICZE ---

    def permute(self, input_val, table, n_bits_input):
        """
        Uniwersalna funkcja permutacji.
        """
        output_val = 0
        table_len = len(table)
        for i in range(table_len):
            # Tabela DES jest indeksowana od 1, dlatego 'table[i] - 1'
            pos = table[i] - 1 
            # Sprawdź bit na pozycji 'pos' (licząc od lewej, czyli od bitu n-1)
            if (input_val >> (n_bits_input - 1 - pos)) & 1:
                output_val |= (1 << (table_len - 1 - i))
        return output_val

    def generate_keys(self, key_64bit):
        """
        Generowanie podkluczy zgodnie z Sekcją 1.1 dokumentacji[cite: 25].
        """
        # 1. PC-1 (64 -> 56 bitów)
        k56 = self.permute(key_64bit, self.PC1_TABLE, 64)
        
        # Podział na C0 i D0 (po 28 bitów) [cite: 28]
        C = (k56 >> 28) & 0x0FFFFFFF
        D = k56 & 0x0FFFFFFF
        
        subkeys = []
        for i in range(self.rounds):
            # Przesunięcie cykliczne w lewo (Tabela 2) [cite: 31, 33]
            shifts = self.SHIFT_TABLE[i]
            C = ((C << shifts) & 0x0FFFFFFF) | (C >> (28 - shifts))
            D = ((D << shifts) & 0x0FFFFFFF) | (D >> (28 - shifts))
            
            # Połączenie C i D
            CD = (C << 28) | D
            
            # 2. PC-2 (56 -> 48 bitów) [cite: 34]
            subkey = self.permute(CD, self.PC2_TABLE, 56)
            subkeys.append(subkey)
            
        return subkeys

    def f_function(self, R, k):
        """
        Funkcja f algorytmu DES (Sekcja 1.3 dokumentacji)[cite: 47].
        """
        # 1. Ekspansja E (32 -> 48 bitów) [cite: 49]
        expanded_R = self.permute(R, self.E_TABLE, 32)
        
        # 2. XOR z kluczem rundy [cite: 52]
        xored = expanded_R ^ k
        
        # 3. S-bloki (Sekcja 1.4) [cite: 53, 58]
        sbox_output = 0
        for i in range(8):
            # Pobranie 6 bitów (blok i)
            # Przesuwamy tak, aby dany blok 6-bitowy znalazł się na pozycjach 0-5
            shift_amount = (7 - i) * 6
            block_6bit = (xored >> shift_amount) & 0x3F
            
            # Wyznaczenie wiersza i kolumny [cite: 61, 62]
            # Wiersz: bit 1 i 6 (indeksy 0 i 5 w notacji 0-indexed)
            row = ((block_6bit >> 5) & 1) * 2 + (block_6bit & 1)
            # Kolumna: bity środkowe
            col = (block_6bit >> 1) & 0x0F
            
            # Pobranie wartości z S-boxa
            val = self.S_BOXES[i][row][col]
            
            # Budowanie wyniku 32-bitowego (8 bloków po 4 bity)
            sbox_output |= (val << ((7 - i) * 4))
            
        # 4. Permutacja P (32 -> 32 bity) [cite: 54, 56]
        return self.permute(sbox_output, self.P_TABLE, 32)

    def run_feistel(self, block_64bit, mode='ENCRYPT'):
        # 1. Permutacja Początkowa IP [cite: 39]
        block = self.permute(block_64bit, self.IP_TABLE, 64)
        
        # Podział na L i R (Sekcja 1.2) [cite: 43]
        L = (block >> 32) & 0xFFFFFFFF
        R = block & 0xFFFFFFFF
        
        # Ustalenie kolejności kluczy
        keys = self.keys if mode == 'ENCRYPT' else self.keys[::-1]
        
        # Pętla Feistela (Rundy)
        for i in range(self.rounds):
            L_prev = L
            R_prev = R
            
            # Główna operacja rundy: L_i = R_{i-1}, R_i = L_{i-1} ^ f(R_{i-1}, K_i) [cite: 48]
            L = R_prev
            R = L_prev ^ self.f_function(R_prev, keys[i])
            
        # UWAGA: Standard DES nie zamienia L i R po ostatniej rundzie (tzw. undo swap).
        # W praktyce oznacza to, że łączymy R|L zamiast L|R przed permutacją końcową. [cite: 44]
        pre_output = (R << 32) | L
        
        # Permutacja Końcowa IP-1 [cite: 44]
        return self.permute(pre_output, self.FP_TABLE, 64)

    def encrypt(self, plaintext):
        return self.run_feistel(plaintext, 'ENCRYPT')

    def decrypt(self, ciphertext):
        return self.run_feistel(ciphertext, 'DECRYPT')

# --- PRZYKŁAD UŻYCIA (Zgodnie z wymaganiami projektu) ---
if __name__ == "__main__":
    import random
    
    # 1. Ustawienia
    ROUNDS = 6  # Bazowo dla projektu badawczego 
    key = 0x133457799BBCDFF1  # Losowy klucz 64-bit
    plaintext = 0x0123456789ABCDEF # Przykładowy tekst
    
    print(f"--- TEST PEŁNEGO DES ({ROUNDS} rund) ---")
    print(f"Klucz: {key:016X}")
    print(f"Tekst jawny: {plaintext:016X}")
    
    # 2. Inicjalizacja
    des = DES(key, rounds=ROUNDS)
    
    # 3. Szyfrowanie
    cipher = des.encrypt(plaintext)
    print(f"Szyfrogram:  {cipher:016X}")
    
    # 4. Deszyfrowanie
    decrypted = des.decrypt(cipher)
    print(f"Odszyfrowany:{decrypted:016X}")
    
    assert plaintext == decrypted, "Błąd! Deszyfrowanie nie powiodło się."
    print("Weryfikacja: SUKCES. Algorytm działa poprawnie.")
    
    # Wyświetlenie podkluczy (by pokazać poprawność Key Schedule)
    print("\nWygenerowane podklucze (pierwsze 3):")
    for i, k in enumerate(des.keys[:3]):
        print(f"Runda {i+1}: {k:012X}")