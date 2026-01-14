import math
from des import DES

class DDTGenerator:
    def __init__(self):
        # Krok 0.1: Załaduj definicję DES (w szczególności S-boxy)
        # Tworzymy instancję DES tylko po to, by mieć dostęp do stałych (S_BOXES)
        # Klucz i rundy nie mają tu znaczenia
        self.des_context = DES(key_int=0, rounds=1)
        self.sboxes = self.des_context.S_BOXES
        
        # Struktury na wyniki
        self.ddt_tables = []       # Surowe liczniki
        self.transitions = []      # Przetworzone wagi i prawdopodobieństwa

    def _sbox_lookup(self, sbox_idx, val_6bit):
        """Pomocnicza funkcja symulująca działanie pojedynczego S-boxa."""
        row = ((val_6bit >> 5) & 1) * 2 + (val_6bit & 1)
        col = (val_6bit >> 1) & 0x0F
        return self.sboxes[sbox_idx][row][col]

    def run_phase_zero(self):
        """Uruchamia wszystkie kroki generowania danych offline."""
        print("--- FAZA 0: Generowanie DDT i wag ---")
        
        for i in range(8):
            # Krok 0.2: Wygeneruj DDT dla każdego S-boxa
            ddt = self._generate_single_ddt(i)
            self.ddt_tables.append(ddt)
            
            # Krok 0.3 i 0.4: Oblicz wagi i przygotuj tablicę przejść
            trans = self._calculate_weights_and_transitions(ddt)
            self.transitions.append(trans)
            
            # Statystyka dla użytkownika
            best_prob = trans[0]['probability'] if trans else 0
            print(f"S-box {i+1}: Znaleziono {len(trans)} możliwych przejść różnicowych.")
            print(f"         Najlepsze prawdopodobieństwo: {best_prob:.4f} (Waga: {trans[0]['weight']:.2f})")

    def _generate_single_ddt(self, sbox_idx):
        # Inicjalizacja tablicy 64x16 zerami
        # Wiersze (64): Różnica wejściowa (Delta_in)
        # Kolumny (16): Różnica wyjściowa (Delta_out)
        ddt = [[0 for _ in range(16)] for _ in range(64)]
        
        # Dla każdej możliwej pary wejść
        # Iterujemy po Delta_in (0..63)
        for delta_in in range(64):
            # Iterujemy po wszystkich możliwych wartościach wejściowych x (0..63)
            for x in range(64):
                # Obliczamy x' (x prime)
                x_prime = x ^ delta_in
                
                # Obliczamy wyjścia z S-boxa
                y = self._sbox_lookup(sbox_idx, x)
                y_prime = self._sbox_lookup(sbox_idx, x_prime)
                
                # Obliczamy Delta_out
                delta_out = y ^ y_prime
                
                # Zwiększamy licznik w DDT
                ddt[delta_in][delta_out] += 1
                
        return ddt

    def _calculate_weights_and_transitions(self, ddt):
        valid_transitions = []
        
        for delta_in in range(64):
            for delta_out in range(16):
                count = ddt[delta_in][delta_out]
                
                if count > 0:
                    # Normalizacja prawdopodobieństwa
                    p = count / 64.0
                    
                    # Krok 0.3: Oblicz wagi (-log2(p))
                    # Unikamy log(0), ale tutaj count > 0, więc jest bezpiecznie
                    weight = int(-math.log2(p) * 1000)
                    
                    # Krok 0.4: Przygotuj wpis
                    entry = {
                        'delta_in': delta_in,
                        'delta_out': delta_out,
                        'weight': weight,
                        'probability': p
                    }
                    valid_transitions.append(entry)
        
        # Sortujemy przejścia od najbardziej prawdopodobnych (najmniejsza waga)
        # Pomijamy trywialny przypadek 0->0 (gdzie p=1, weight=0), chyba że jest potrzebny
        valid_transitions.sort(key=lambda x: x['weight'])
        
        return valid_transitions

    def get_best_transition(self, sbox_idx, delta_in):
        """Zwraca najbardziej prawdopodobną różnicę wyjściową dla danej wejściowej."""
        # Filtrujemy przejścia dla danego delta_in
        options = [t for t in self.transitions[sbox_idx] if t['delta_in'] == delta_in]
        if not options:
            return 0, 0 # Brak przejścia (nie powinno się zdarzyć dla count>0)
        
        # options są już posortowane wagami rosnąco, więc pierwszy jest najlepszy
        return options[0]['delta_out'], options[0]['probability']