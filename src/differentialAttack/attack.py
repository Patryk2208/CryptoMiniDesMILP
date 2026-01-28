from des import DES


class DifferentialAttackDES:
    def __init__(self, des_cipher: DES, characteristic):
        """
        Inicjalizacja ataku różnicowego

        Args:
            des_cipher: obiekt DES (musi mieć metody encrypt(key, plaintext))
            characteristic: słownik z charakterystyką:
                {
                    'input_diff': (L0_hex, R0_hex),
                    'output_diff': (LR_hex, RR_hex),
                    'round_diffs': [(L1,R1), (L2,R2), ...],
                    'transitions': lista przejść S-boksów
                }
            probability: prawdopodobieństwo charakterystyki (float)
        """
        self.des = des_cipher
        self.characteristic = characteristic

        self.probability = pow(2, -self.characteristic['objective_value'] / 1000)

        # Oblicz ile par potrzebujemy
        self.required_pairs = int(1.0 / self.probability) * 10  # 3x dla pewności

        print(f"Charakterystyka różnicowa: p = {self.probability:.2e}")
        print(f"Wymagana liczba par: ~{self.required_pairs}")
        print(f"Różnica wejściowa: {characteristic['input_diff']}")
        print(f"Różnica wyjściowa: {characteristic['output_diff']}")

    def collect_plaintext_pairs(self, num_pairs=None):
        """
        Zbiera pary plaintextów z zadaną różnicą

        Returns:
            Lista par [(P1, P1'), (P2, P2'), ...]
        """
        if num_pairs is None:
            num_pairs = self.required_pairs

        pairs = []
        delta_L, delta_R = self.characteristic['input_diff']
        # 1. Złóż wewnętrzną różnicę oczekiwaną przez MILP (L0 || R0)
        delta_internal = (int(delta_L, 16) << 32) | int(delta_R, 16)
        
        # 2. Zastosuj FP (odwrotność IP), aby uzyskać różnicę w Plaintext
        # Delta Plaintext = IP_inv(Delta Internal) = FP(Delta Internal)
        delta_int = self.des.permute(delta_internal, self.des.FP_TABLE, 64)

        print(f"Zbieranie {num_pairs} par plaintextów z ΔP = {hex(delta_int)}...")

        for _ in range(num_pairs):
            # Losowy plaintext P
            P = self._random_64bit()
            # P' = P ⊕ ΔP
            P_prime = P ^ delta_int
            pairs.append((P, P_prime))

        print(f"Zebrano {len(pairs)} par")
        return pairs

    def filter_correct_pairs(self, pairs):
        """
        Filtruje pary które podążają charakterystyką

        Returns:
            Lista par które dają oczekiwaną różnicę wyjściową
        """
        print(f"Filtrowanie par z prawdziwym kluczem (symulacja)...")

        correct_pairs = []
        L_end_milp = int(self.characteristic['output_diff'][0], 16)
        R_end_milp = int(self.characteristic['output_diff'][1], 16)
        
        # KROK 2: Złóż je tak, jak robi to DES przed permutacją FP (czyli R || L)
        pre_output = (R_end_milp << 32) | L_end_milp
        
        # KROK 3: Zastosuj permutację FP (musisz mieć dostęp do FP_TABLE)
        # Możesz to zrobić używając instancji des
        delta_C_int = self.des.permute(pre_output, self.des.FP_TABLE, 64)
        
        # Teraz delta_C jest gotowa do porównania z C ^ C_prime
        delta_C = delta_C_int
        min_diff = 32
        min_diff_cipher = hex(0)
        min_count = 0
        all_diffs = []

        for P, P_prime in pairs:
            C = self.des.encrypt(P)
            C_prime = self.des.encrypt(P_prime)

            delta = hex(C ^ C_prime)
            diff = (C ^ C_prime) ^ delta_C
            if diff.bit_count() < min_diff:
                min_diff = diff.bit_count()
                min_diff_cipher = delta

            all_diffs.append(delta)

            if (C ^ C_prime) == delta_C:
                correct_pairs.append((P, P_prime, C, C_prime))

        print(f"Najmniejsza roznica to {min_diff} dla {min_diff_cipher}, {min_count} razy")
        print(f"Znaleziono {len(correct_pairs)} par podążających charakterystyką "
              f"(oczekiwano ~{len(pairs) * self.probability:.1f})")
        return correct_pairs, all_diffs, delta_C


    def attack_last_round_key(self, filtered_pairs):
        """
        Atak na klucz ostatniej rundy przy użyciu poprawnych par (Right Pairs).
        """
        print("\n" + "=" * 60)
        print("ATAK NA KLUCZ OSTATNIEJ RUNDY")
        print("=" * 60)
        
        if not filtered_pairs:
            print("Brak par do analizy.")
            return {}, {}

        # Potrzebujemy różnicy wejściowej do ostatniej rundy (L_{n-1}).
        # W charakterystyce round_diffs[r] to stan po rundzie r.
        # Jeśli atakujemy 6-rundowy DES, to input do ostatniej rundy to stan po rundzie 5.
        # UWAGA: output_diff to stan po ostatniej rundzie.
        # round_diffs[-1] to output_diff. round_diffs[-2] to stan przed ostatnią rundą.
        
        # Sprawdzamy czy mamy historię rund
        if len(self.characteristic['round_diffs']) >= 2:
            # Stan po przedostatniej rundzie: (L_{n-1}, R_{n-1})
            # L_{n-1} jest nam potrzebne, bo F(R_{n-1}) ^ L_{n-1} = R_n
            # Delta F = Delta R_n ^ Delta L_{n-1}
            # Delta wejścia do F = Delta R_{n-1}
            prev_round_diff = self.characteristic['round_diffs'][-2]
            delta_L_prev = int(prev_round_diff[0], 16)
        else:
            # Fallback dla 1 rundy (L_{n-1} to L0)
            delta_L_prev = int(self.characteristic['input_diff'][0], 16)
            
        print(f"Używam Delta L_{{n-1}} z charakterystyki: {hex(delta_L_prev)}")

        # Liczniki dla każdego S-boxa (8 sboxów, 64 możliwe klucze każdy)
        key_counters = [{k: 0 for k in range(64)} for _ in range(8)]

        for idx, (_, _, C, C_prime) in enumerate(filtered_pairs):
            # 1. Cofnij permutację FP, aby uzyskać surowy wynik rundy n (R_n || L_n)
            # Używamy IP, bo IP = FP^-1
            C_raw = self.des.permute(C, self.des.IP_TABLE, 64)
            C_prime_raw = self.des.permute(C_prime, self.des.IP_TABLE, 64)

            # 2. Rozdziel na L_n i R_n
            # W core.py pre_output = (R << 32) | L. 
            # Czyli górne 32 bity to R_n, dolne to L_n (które jest równe R_{n-1})
            R_n = (C_raw >> 32) & 0xFFFFFFFF
            L_n = C_raw & 0xFFFFFFFF
            
            R_n_prime = (C_prime_raw >> 32) & 0xFFFFFFFF
            L_n_prime = C_prime_raw & 0xFFFFFFFF

            # 3. Wyznacz różnicę na wyjściu funkcji F
            # R_n = L_{n-1} ^ F(R_{n-1}, K_n)
            # Delta R_n = Delta L_{n-1} ^ Delta F
            # Delta F = Delta R_n ^ Delta L_{n-1}
            delta_R_n = R_n ^ R_n_prime
            target_F_diff = delta_R_n ^ delta_L_prev

            # 4. Przygotuj wejścia do funkcji F (czyli R_{n-1} = L_n)
            R_prev = L_n
            R_prev_prime = L_n_prime
            
            # Rozszerzenie E (32 -> 48)
            E_out = self.des.permute(R_prev, self.des.E_TABLE, 32)
            E_out_prime = self.des.permute(R_prev_prime, self.des.E_TABLE, 32)

            # Analiza każdego S-boxa niezależnie
            for sbox in range(8):
                # Pozycja bitów dla danego S-boxa w 48-bitowym bloku E
                # S1 to bity 0-5 (najstarsze), S8 to 42-47
                # ALE w des.py S-boxy są iterowane od 0..7 i pobierane z shiftem.
                # Sprawdźmy core.py -> f_function:
                # shift_amount = (7 - i) * 6. Czyli S0 (i=0) bierze bity przesunięte o 42 (najstarsze).
                # To oznacza, że E_out ma układ S1 S2 ... S8 od najstarszych bitów.
                
                # Wyciągamy 6 bitów wejścia dla S-boxa `sbox`
                # Przesunięcie jak w core.py
                shift = (7 - sbox) * 6
                mask = 0x3F
                
                sbox_in = (E_out >> shift) & mask
                sbox_in_prime = (E_out_prime >> shift) & mask
                
                # Delta wejściowa do S-boxa (nie zależy od klucza)
                delta_in_sbox = sbox_in ^ sbox_in_prime
                
                # Teraz musimy sprawdzić, czy dane kandydata k na klucz generują wyjście S-boxa,
                # które pasuje do target_F_diff.
                
                # Problem: target_F_diff jest po permutacji P.
                # Nie możemy łatwo cofnąć P tylko dla fragmentu.
                # Ale możemy obliczyć wyjście S-boxa, przepuścić przez P i sprawdzić czy pasuje do bitów target_F_diff.
                
                # Permutacja P w DES (core.py) mapuje bity wyjścia S-boxów na 32-bitowe słowo.
                # Musimy wiedzieć, które bity w 32-bitowym F_out pochodzą od naszego S-boxa.
                # Zrobimy to symulacyjnie: ustawimy wyjście S-boxa na 0xF (wszystkie 1), resztę na 0,
                # przepuścimy przez P i zobaczymy które bity się zapalą.
                
                test_val_sbox = 0xF << ((7 - sbox) * 4) # Wyjście S-boxa jest na odpowiedniej pozycji przed P
                p_mask = self.des.permute(test_val_sbox, self.des.P_TABLE, 32)
                
                # Oczekiwana różnica na bitach zależnych od tego S-boxa
                target_sbox_part = target_F_diff & p_mask

                for k in range(64):
                    # XOR z kluczem (hipoteza)
                    # Uwaga: k to 6-bitowy fragment klucza
                    real_in = sbox_in ^ k
                    real_in_prime = sbox_in_prime ^ k
                    
                    # Oblicz wyjście S-boxa
                    val = self._sbox_lookup(sbox, real_in)
                    val_prime = self._sbox_lookup(sbox, real_in_prime)
                    
                    diff_val = val ^ val_prime
                    
                    # Umieść różnicę na odpowiedniej pozycji przed permutacją P
                    diff_val_shifted = diff_val << ((7 - sbox) * 4)
                    
                    # Przepuść przez P
                    permuted_diff = self.des.permute(diff_val_shifted, self.des.P_TABLE, 32)
                    
                    # Sprawdź czy pasuje do obserwowanego wyjścia F
                    if (permuted_diff & p_mask) == target_sbox_part:
                        key_counters[sbox][k] += 1

            if (idx + 1) % 100 == 0:
                 print(f"  Przetworzono {idx + 1}/{len(filtered_pairs)} par")

        # Wybór najlepszych kluczy
        best_keys = {}
        print("\nWYNIKI ATAKU:")
        for sbox in range(8):
            # Sortuj malejąco po liczbie głosów
            sorted_candidates = sorted(key_counters[sbox].items(), key=lambda x: x[1], reverse=True)
            best_k = sorted_candidates[0]
            
            best_keys[sbox] = (best_k[0], best_k[1]) # (klucz, licznik)
            
            # Pokaż top 3 kandydatów
            top3 = [f"{k:02x}({c})" for k, c in sorted_candidates[:3]]
            print(f"  S-box {sbox+1}: Zwycięzca: {best_k[0]:02x} (głosów: {best_k[1]}/{len(filtered_pairs)}). Top3: {top3}")

        return best_keys, key_counters

    def full_attack(self, unknown_key):
        """
        Przeprowadza pełny atak
        """
        print("=" * 60)
        print("ROZPOCZĘCIE PEŁNEGO ATAKU RÓŻNICOWEGO")
        print("=" * 60)

        # KROK 1: Zbierz pary plaintextów
        pairs = self.collect_plaintext_pairs()

        # KROK 2: Filtruj pary które podążają charakterystyką
        filtered_pairs, _, _ = self.filter_correct_pairs(pairs)

        if len(filtered_pairs) == 0:
            print("\n⚠️ BRAK PAR PODĄŻAJĄCYCH CHARAKTERYSTYKĄ!")
            return None

        # KROK 3: Atak na klucz ostatniej rundy
        best_keys, counters = self.attack_last_round_key(filtered_pairs)

        # KROK 4: Weryfikacja (symulowana)
        # Tutaj w prawdziwym ataku nastąpiłoby brute-force brakujących bitów
        # i weryfikacja na pełnym szyfrowaniu.
        
        # Sprawdźmy poprawność znalezionych podkluczy (dla celów edukacyjnych)
        self._verify_key_simulation(best_keys, unknown_key)
        
        return best_keys

    def _sbox_lookup(self, sbox_idx, val_6bit):
        """Pomocnicza funkcja symulująca działanie pojedynczego S-boxa."""
        row = ((val_6bit >> 5) & 1) * 2 + (val_6bit & 1)
        col = (val_6bit >> 1) & 0x0F
        return self.des.S_BOXES[sbox_idx][row][col]

    def _random_64bit(self):
        import random
        return random.getrandbits(64)

    def _verify_key_simulation(self, best_keys, true_key_full):
        """
        Weryfikuje znalezione podklucze z prawdziwym kluczem (tylko do symulacji/testów).
        """
        print("\n" + "=" * 60)
        print("WERYFIKACJA (TYLKO SYMULACJA)")
        print("=" * 60)
        
        # Musimy wygenerować prawdziwy podklucz dla ostatniej rundy
        # DES generuje klucze dla rund 0..rounds-1. 
        # Jeśli atakujemy 6-rundowy DES, interesuje nas klucz rundy 5 (czyli ostatni).
        
        # Generujemy wszystkie podklucze
        round_keys = self.des.generate_keys(true_key_full)
        # Klucz ostatniej rundy
        last_round_key = round_keys[-1] # round_keys[rounds-1]
        
        print(f"Prawdziwy klucz ostatniej rundy (48 bit): {hex(last_round_key)}")
        
        correct_cnt = 0
        for sbox in range(8):
            # Wyciągnij 6 bitów dla danego S-boxa z prawdziwego klucza
            # W generate_keys klucz jest 48-bitową liczbą. 
            # Bity dla S1 są najstarsze (tak jak w E_out).
            shift = (7 - sbox) * 6
            true_sbox_key = (last_round_key >> shift) & 0x3F
            
            guessed_key = best_keys[sbox][0]
            
            match = (true_sbox_key == guessed_key)
            status = "✅ OK" if match else f"❌ BŁĄD (Oczekiwano: {true_sbox_key:02x})"
            
            print(f"  S-box {sbox+1}: Zgadnięto: {guessed_key:02x} -> {status}")
            if match: correct_cnt += 1
            
        print(f"\nSkuteczność: {correct_cnt}/8 podkluczy poprawne.")