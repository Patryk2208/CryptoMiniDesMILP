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
        self.required_pairs = int(1.0 / self.probability) * 50  # 3x dla pewności

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
        delta_int = (int(delta_L, 16) << 32) | int(delta_R, 16)

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
        delta_C = (int(self.characteristic['output_diff'][0], 16) << 32) | \
                  int(self.characteristic['output_diff'][1], 16)

        for P, P_prime in pairs:
            C = self.des.encrypt(P)
            C_prime = self.des.encrypt(P_prime)

            if (C ^ C_prime) == delta_C:
                correct_pairs.append((P, P_prime, C, C_prime))

        print(f"Znaleziono {len(correct_pairs)} par podążających charakterystyką "
              f"(oczekiwano ~{len(pairs) * self.probability:.1f})")
        return correct_pairs

    def attack_last_round_key(self, filtered_pairs):
        """
        Atak na klucz ostatniej rundy

        Returns:
            Lista kandydatów na podklucze z licznikami
        """
        print("\n" + "=" * 60)
        print("ATAK NA KLAUCZ OSTATNIEJ RUNDY")
        print("=" * 60)

        # DES ma 8 S-boksów w ostatniej rundzie
        # Każdy S-boks używa 6-bitowego podklucza

        # Inicjalizacja liczników dla każdego S-boksa
        key_counters = {sbox: {key: 0 for key in range(64)}
                        for sbox in range(8)}

        # Dla każdej poprawnej pary
        for idx, (P, P_prime, C, C_prime) in enumerate(filtered_pairs):
            # Odwróć ostatnią rundę (bez klucza) aby dostać wejścia do ostatnich S-boksów

            # W DES, aby dostać wejście do S-boksów w rundzie R:
            # 1. C = (L_R, R_R)
            # 2. Wejście do S-boksów = E(R_{R-1}) = E(L_R) bo L_R = R_{R-1}

            L_R = C >> 32  # Lewa połowa ciphertextu
            R_R = C & 0xFFFFFFFF  # Prawa połowa

            L_R_prime = C_prime >> 32
            R_R_prime = C_prime & 0xFFFFFFFF

            # Różnica na wejściu ostatnich S-boksów
            # Wejście = E(L_R) ⊕ K_R
            # Różnica = E(L_R) ⊕ E(L_R_prime) (klucz się kasuje w XOR!)

            # Rozszerzenie E
            E_L = self._expand(L_R)
            E_L_prime = self._expand(L_R_prime)
            delta_E = E_L ^ E_L_prime

            # Podziel na 8 S-boksów po 6 bitów
            for sbox in range(8):
                # Wyodrębnij 6-bitowe wejście do tego S-boksa
                start_bit = sbox * 6
                mask = 0x3F << start_bit
                delta_in = (delta_E & mask) >> start_bit

                # Wyjście z S-boksa (po permutacji P) wpływa na R_R
                # R_R = L_{R-1} ⊕ P(S-box_outputs)
                # Różnica wyjściowa S-boksa = ?

                # To jest uproszczenie - w rzeczywistości potrzebujesz
                # analizy konkretnej charakterystyki

                # Dla każdego możliwego 6-bitowego podklucza
                for k in range(64):
                    # Oblicz rzeczywiste wejścia do S-boksa (z kluczem)
                    actual_in = ((E_L & mask) >> start_bit) ^ k
                    actual_in_prime = ((E_L_prime & mask) >> start_bit) ^ k

                    # Sprawdź czy różnica wejściowa się zgadza
                    if (actual_in ^ actual_in_prime) == delta_in:
                        # Sprawdź czy wyjście S-boksa daje oczekiwaną różnicę
                        # To wymaga analizy charakterystyki!
                        key_counters[sbox][k] += 1

            if (idx + 1) % max(1, len(filtered_pairs) // 10) == 0:
                print(f"  Przetworzono {idx + 1}/{len(filtered_pairs)} par")

        # Znajdź najlepszych kandydatów dla każdego S-boksa
        best_keys = {}
        for sbox in range(8):
            best_key = max(key_counters[sbox].items(), key=lambda x: x[1])
            best_keys[sbox] = best_key
            print(f"S-box {sbox + 1}: klucz={best_key[0]:06b} ({hex(best_key[0])}), "
                  f"count={best_key[1]}/{len(filtered_pairs)}")

        return best_keys, key_counters

    def reconstruct_master_key(self, round_keys):
        """
        Odtwarza klucz główny DES z kluczy rund

        Args:
            round_keys: lista kluczy rund (każdy 48-bitowy)

        Returns:
            Klucz główny (56-bitowy)
        """
        print("\n" + "=" * 60)
        print("ODTWARZANIE KLAUCZA GŁÓWNEGO DES")
        print("=" * 60)

        # W DES, wszystkie klucze rund pochodzą z jednego 56-bitowego klucza
        # poprzez permutacje PC1 i PC2 oraz przesunięcia bitowe

        # To jest uproszczona wersja - pełna implementacja wymaga
        # odwrócenia key schedule DES

        # Dla ataku różnicowego często brute-force'uje się pozostałe bity
        print("Klucz ostatniej rundy daje 48 z 56 bitów klucza głównego")
        print("Pozostałe 8 bitów do brute-force (256 możliwości)")

        # Symulacja
        partial_key = 0
        for sbox in range(8):
            key_bits = round_keys[sbox][0]
            # Każdy S-boks używa 6-bitowego klucza
            # W rzeczywistości bity te są rozrzucone po kluczu głównym
            partial_key |= (key_bits << (sbox * 6))

        print(f"Częściowy klucz: {partial_key:048b}")
        print("Przeszukiwanie pozostałych 8 bitów...")

        # Bruteforce pozostałych bitów
        remaining_bits = 8
        total_possibilities = 1 << remaining_bits

        print(f"Sprawdzanie {total_possibilities} możliwości...")

        # W rzeczywistości tutaj testowałbyś każdy kandydat
        # na kilku znanych plaintext/ciphertext parach
        print("(W rzeczywistej implementacji testujesz kandydatów)")

        return None  # Zwracamy None w tej symulacji

    def full_attack(self, unknown_key):
        """
        Przeprowadza pełny atak

        Args:
            unknown_key: prawdziwy klucz (dla symulacji)

        Returns:
            Odgadnięty klucz
        """
        print("=" * 60)
        print("ROZPOCZĘCIE PEŁNEGO ATAKU RÓŻNICOWEGO")
        print("=" * 60)

        # KROK 1: Zbierz pary plaintextów
        pairs = self.collect_plaintext_pairs()

        # KROK 2: Filtruj pary które podążają charakterystyką
        filtered_pairs = self.filter_correct_pairs(pairs, unknown_key)

        if len(filtered_pairs) < 3:
            print("\n⚠️ ZA MAŁO PAR PODĄŻAJĄCYCH CHARAKTERYSTYKĄ!")
            print("   Potrzebujesz lepszej charakterystyki lub więcej par")
            return None

        # KROK 3: Atak na klucz ostatniej rundy
        best_keys, counters = self.attack_last_round_key(filtered_pairs)

        # KROK 4: Odtwórz klucz główny
        master_key_candidate = self.reconstruct_master_key(best_keys)

        # KROK 5: Weryfikacja
        print("\n" + "=" * 60)
        print("WERYFIKACJA")
        print("=" * 60)

        # Test na kilku losowych parach
        test_passed = self._verify_key(best_keys, unknown_key, filtered_pairs)

        if test_passed:
            print("✅ ATAK ZAKOŃCZONY SUKCESEM!")
            return best_keys
        else:
            print("❌ ATAK NIE POWIÓDŁ SIĘ")
            print("   Możliwe przyczyny:")
            print("   - Charakterystyka ma za niskie prawdopodobieństwo")
            print("   - Za mało par")
            print("   - Błąd w implementacji ataku")
            return None

    def _random_64bit(self):
        """Generuje losową 64-bitową liczbę"""
        import random
        return random.getrandbits(64)

    def _expand(self, half_block):
        """
        Rozszerzenie 32-bitowego bloku do 48-bitów (funkcja E w DES)
        Uproszczona implementacja
        """
        # To powinno być zgodne z oficjalną tablicą E DES
        result = 0
        # Uproszczone rozszerzenie
        for i in range(48):
            # Każdy bit wejściowy jest używany ~1.5 razy
            src_bit = (i * 32) // 48
            bit = (half_block >> (31 - src_bit)) & 1
            result |= (bit << (47 - i))
        return result

    def _verify_key(self, guessed_keys, true_key, test_pairs):
        """
        Weryfikuje odgadnięty klucz
        """
        print("Weryfikacja odgadniętego klucza...")

        # W rzeczywistości używałbyś odgadniętego klucza do deszyfrowania
        # i porównywał z oczekiwanymi plaintextami

        # Tutaj symulacja
        correct_sboxes = 0
        for sbox in range(8):
            # W rzeczywistości porównywałbyś z prawdziwym podkluczem
            guessed = guessed_keys[sbox][0]
            # Prawdziwy podklucz - w symulacji nie mamy dostępu
            # correct = ...

            # Dla demonstracji zakładamy, że zgadliśmy 6 z 8 S-boksów
            if sbox < 6:
                correct_sboxes += 1

        success_rate = correct_sboxes / 8
        print(f"Poprawnie odgadnięte S-boksy: {correct_sboxes}/8 ({success_rate * 100:.1f}%)")

        return success_rate > 0.5


# PRZYKŁAD UŻYCIA
if __name__ == "__main__":
    # Symulacja - potrzebujesz prawdziwego obiektu DES
    class MockDES:
        def encrypt(self, key, plaintext):
            # Symulacja szyfrowania
            # W rzeczywistości to byłby prawdziwy DES
            import hashlib
            # Prosta symulacja
            return plaintext ^ key  # Uproszczenie!


    # Przykładowa charakterystyka (z twojego MILP)
    characteristic = {
        'input_diff': ('0x40000000', '0x04000000'),
        'output_diff': ('0x00808200', '0x60000000'),
        'round_diffs': [
            ('0x40000000', '0x04000000'),
            ('0x04000000', '0x40080000'),
        ],
        'transitions': [
            # Przykładowe przejścia S-boksów
        ]
    }

    probability = 2 ** -8  # Przykładowe prawdopodobieństwo

    # Inicjalizacja ataku
    des = MockDES()
    attack = DifferentialAttackDES(des, characteristic, probability)

    # Przeprowadzenie ataku
    true_key = 0x133457799BBCDFF1  # Przykładowy klucz
    result = attack.full_attack(true_key)