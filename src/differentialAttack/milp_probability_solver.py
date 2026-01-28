from pulp import LpProblem, LpVariable, LpBinary, LpMinimize, lpSum, LpStatus
import itertools
from src.des import DES
from src.differentialAttack.ddt import DDTGenerator


class DES_MILP_Solver:
    def __init__(self, des:DES, input_diff_L, input_diff_R, num_rounds=3, cutoff=0):
        """
        Inicjalizacja solvera MILP dla DES
        Args:
            num_rounds: liczba rund DES (R)
        """
        self.ddt_generator = DDTGenerator(cutoff=cutoff)
        self.ddt_generator.run_phase_zero()

        self.Rounds = num_rounds

        self.input_diff_L = input_diff_L
        self.input_diff_R = input_diff_R

        self.des = des

        # Tablice permutacji DES (uproszczone, tylko niezbędne dla różnic)
        self.ExpansionTable = [x - 1 for x in des.E_TABLE]

        self.P = [x - 1 for x in des.P_TABLE]

        # Mapowanie S-boksów: które bity E_r idą do którego S-boksu
        self.S_box_mapping = {}
        for sbox in range(8):
            start_bit = sbox * 6
            self.S_box_mapping[sbox] = list(range(start_bit, start_bit + 6))

        # Problem MILP
        self.problem = LpProblem("DES_Differential_Cryptanalysis", LpMinimize)

        # Inicjalizacja wszystkich zmiennych
        self._create_variables()

        # Dodanie wszystkich ograniczeń
        self._add_constraints()

        # Ustawienie funkcji celu
        self._set_objective()

    def _create_variables(self):
        """Tworzy wszystkie zmienne opisane w specyfikacji"""
        print(f"Tworzenie zmiennych dla {self.Rounds} rund...")

        # 1. ZMIENNE STANU
        self.L = {}  # L_r[b] lsb===0 indexing
        self.R = {}  # R_r[b] lsb===0 indexing

        for r in range(self.Rounds + 1):  # 0..R
            for b in range(32):
                self.L[(r, b)] = LpVariable(f"L_{r}_{b}", 0, 1, LpBinary)
                self.R[(r, b)] = LpVariable(f"R_{r}_{b}", 0, 1, LpBinary)

        # 2. ZMIENNE FUNKCJI F
        self.E = {}  # E_r[e]
        self.F = {}  # F_r[b]

        for r in range(1, self.Rounds + 1):  # 1..R
            for e in range(48):
                self.E[(r, e)] = LpVariable(f"E_{r}_{e}", 0, 1, LpBinary)
            for b in range(32):
                self.F[(r, b)] = LpVariable(f"F_{r}_{b}", 0, 1, LpBinary)

        # 3. ZMIENNE S-BOKSÓW
        self.S_in = {}  # S_in_{r,i}[k]
        self.S_out = {}  # S_out_{r,i}[m]

        for r in range(1, self.Rounds + 1):
            for i in range(8):  # 0..7 dla S-boksów
                for k in range(6):
                    self.S_in[(r, i, k)] = LpVariable(f"S_in_{r}_{i}_{k}", 0, 1, LpBinary)
                for m in range(4):
                    self.S_out[(r, i, m)] = LpVariable(f"S_out_{r}_{i}_{m}", 0, 1, LpBinary)

        # 4. ZMIENNE WYBORU PRZEJŚĆ (TUTAJ SYMULUJEMY - PRAWDZIWE BĘDĄ Z DDT)
        # Najpierw tworzymy sztuczne przejścia dla demonstracji
        # W rzeczywistości będą ładowane z DDT
        self.transitions = self.ddt_generator.transitions  # Przechowuje informacje o przejściach
        self.T = {}  # T_{r,i,t} - zmienne wyboru przejść


        # Teraz tworzymy zmienne wyboru dla każdego przejścia
        for r in range(1, self.Rounds + 1):
            for i in range(8):
                for t_idx, _ in enumerate(self.transitions[i]):
                    self.T[(r, i, t_idx)] = LpVariable(
                        f"T_{r}_{i}_{t_idx}", 0, 1, LpBinary
                    )

        # 5. ZMIENNE POMOCNICZE DLA XOR
        self.xor_vars = {}  # xor_{r,b}
        for r in range(1, self.Rounds + 1):
            for b in range(32):
                self.xor_vars[(r, b)] = LpVariable(f"xor_{r}_{b}", 0, 1, LpBinary)

        print(f"Utworzono zmienne:")
        print(f"  Stan: {2 * (self.Rounds + 1) * 32}")
        print(f"  Funkcja F: {self.Rounds * 48 + self.Rounds * 32}")
        print(f"  S-boksy: {self.Rounds * 8 * 6 + self.Rounds * 8 * 4}")
        print(f"  Przejścia: {self.Rounds * 8 * len(self.transitions[0])}")
        print(f"  XOR helper: {self.Rounds * 32}")

    def _add_constraints(self):
        """Dodaje wszystkie ograniczenia do modelu"""
        print("Dodawanie ograniczeń...")

        # 1. USTALENIE RÓŻNICY POCZĄTKOWEJ
        # Przykładowa dobra różnica dla DES
        # W praktyce można to parametrizać
        self._set_input_difference()

        # 2. OGRANICZENIA DLA KAŻDEJ RUNDY
        for r in range(1, self.Rounds + 1):
            self._add_round_constraints(r)

        # 3. OGRANICZENIE UNIKAJĄCE TRYWIALNEGO ROZWIĄZANIA
        # Wymuszamy, że różnica wyjściowa nie jest zerowa
        self._add_non_trivial_constraint()

        print("Wszystkie ograniczenia dodane.")

    def _set_input_difference(self):
        """Ustala różnicę wejściową (przykładowa dobra różnica dla DES)"""

        for i in range(32):
            bitL = (self.input_diff_L >> (31 - i)) & 1
            bitR = (self.input_diff_R >> (31 - i)) & 1

            self.problem += self.L[(0, i)] == bitL
            self.problem += self.R[(0, i)] == bitR


    def _add_round_constraints(self, r):
        """Dodaje ograniczenia dla rundy r"""
        print(f"  Dodawanie ograniczeń dla rundy {r}...")

        # 1. ROZSZERZENIE E: E_r = E(R_{r-1})
        self._add_expansion_constraints(r)

        # 2. WEJŚCIE DO S-BOKSÓW: S_in z E_r
        self._add_sbox_input_constraints(r)

        # 3. WYBÓR PRZEJŚĆ S-BOKSÓW I WYJŚCIE
        self._add_sbox_transition_constraints(r)

        # 4. PERMUTACJA P: F_r z S_out
        self._add_permutation_constraints(r)

        # 5. STRUKTURA FEISTELA
        self._add_feistel_constraints(r)

    def _add_expansion_constraints(self, r):
        """E_r[e] = R_{r-1}[E[e]] gdzie E to tablica expansion"""
        for e in range(48):
            source_bit = self.ExpansionTable[e]  # Który bit R_{r-1} kopiujemy
            self.problem += self.E[(r, e)] == self.R[(r - 1, source_bit)]

    def _add_sbox_input_constraints(self, r):
        """S_in_{r,i} pobiera 6 bitów z E_r"""
        for i in range(8):
            for k in range(6):
                # Który bit E_r odpowiada bitowi k wejścia S-boksa i
                e_bit = i * 6 + k
                self.problem += self.S_in[(r, i, k)] == self.E[(r, e_bit)]

    def _add_sbox_transition_constraints(self, r):
        """
        Najważniejsze! Łączy wybór przejścia z wejściem/wyjściem S-boksa.
        Dla każdego S-boksa i w rundzie r:
        - Dokładnie jedno przejście jest wybrane
        - Jeśli przejście t jest wybrane, to S_in = delta_in(t) i S_out = delta_out(t)
        """
        M = 10  # Duża stała dla linearizacji

        for i in range(8):
            # Ograniczenie: suma wybranych przejść = 1
            transition_vars = [self.T[(r, i, t_idx)]
                               for t_idx in range(len(self.transitions[i]))]
            self.problem += lpSum(transition_vars) == 1
            
            # Dla każdego możliwego przejścia
            for t_idx, transition in enumerate(self.transitions[i]):
                t_var = self.T[(r, i, t_idx)]
                delta_in = transition['delta_in']
                delta_out = transition['delta_out']

                # Bitowa reprezentacja delta_in (6 bitów)
                delta_in_bits = [(delta_in >> bit) & 1 for bit in range(5, -1, -1)]
                # Bitowa reprezentacja delta_out (4 bity)
                delta_out_bits = [(delta_out >> bit) & 1 for bit in range(3, -1, -1)]

                # IMPLIKACJA: Jeśli t_var = 1, to S_in = delta_in
                for k in range(6):
                    # S_in[k] = delta_in_bits[k] gdy t_var = 1
                    # Linearizacja: S_in[k] - delta_in_bits[k] <= M*(1 - t_var)
                    #               delta_in_bits[k] - S_in[k] <= M*(1 - t_var)
                    self.problem += (self.S_in[(r, i, k)] - delta_in_bits[k] <= M * (1 - t_var))
                    self.problem += (delta_in_bits[k] - self.S_in[(r, i, k)] <= M * (1 - t_var))

                # IMPLIKACJA: Jeśli t_var = 1, to S_out = delta_out
                for m in range(4):
                    self.problem += (self.S_out[(r, i, m)] - delta_out_bits[m] <= M * (1 - t_var))
                    self.problem += (delta_out_bits[m] - self.S_out[(r, i, m)] <= M * (1 - t_var))

    def _add_permutation_constraints(self, r):
        """F_r[b] = S_out_{r,i}[k] zgodnie z permutacją P"""
        # P jest zdefiniowane jako mapowanie bitów wyjścia F do bitów S_out
        # W DES: bit b wyjścia F pochodzi z bitu P[b] z połączonych wyjść S-boksów

        # Najpierw tworzymy 32-bitowe wyjście z S-boksów
        sbox_output_bits = []
        for i in range(8):
            for m in range(4):
                sbox_output_bits.append(self.S_out[(r, i, m)])

        # Teraz permutacja: F_r[b] = sbox_output_bits[P[b]]
        for b in range(32):
            source_bit = self.P[b]
            self.problem += self.F[(r, b)] == sbox_output_bits[source_bit]

    def _add_feistel_constraints(self, r):
        """Struktura Feistela: L_r = R_{r-1}, R_r = L_{r-1} XOR F_r"""
        # L_r = R_{r-1} (proste kopiowanie)
        for b in range(32):
            self.problem += self.L[(r, b)] == self.R[(r - 1, b)]

        # R_r = L_{r-1} XOR F_r (trzeba zlinearyzować XOR)
        for b in range(32):
            l_bit = self.L[(r - 1, b)]
            f_bit = self.F[(r, b)]
            r_bit = self.R[(r, b)]
            xor_var = self.xor_vars[(r, b)]

            # Linearizacja XOR: x = y XOR z
            # Reprezentacja przez 4 nierówności
            self.problem += r_bit <= l_bit + f_bit
            self.problem += r_bit >= l_bit - f_bit
            self.problem += r_bit >= f_bit - l_bit
            self.problem += r_bit <= 2 - l_bit - f_bit

            # Alternatywnie można użyć zmiennej pomocniczej xor_var
            # ale powyższa metoda jest prostsza

    def _add_non_trivial_constraint(self):
        """Wymusza, że różnica wyjściowa nie jest zerowa"""
        # Suma wszystkich bitów różnicy wyjściowej >= 1
        output_bits = []
        for b in range(32):
            output_bits.append(self.L[(self.Rounds, b)])
            output_bits.append(self.R[(self.Rounds, b)])

        self.problem += lpSum(output_bits) >= 1

    def _set_objective(self):
        """Ustawia funkcję celu: minimalizacja sumy wag wybranych przejść"""
        print("Ustawianie funkcji celu...")

        objective_terms = []

        for r in range(1, self.Rounds + 1):
            for i in range(8):
                for t_idx, transition in enumerate(self.transitions[i]):
                    weight = transition['weight']
                    t_var = self.T[(r, i, t_idx)]
                    objective_terms.append(weight * t_var)

        self.problem += lpSum(objective_terms)
        print(f"Funkcja celu ustawiona: minimalizacja sumy {len(objective_terms)} wag.")

    def solve(self, time_limit=60):
        """Rozwiązuje problem MILP"""
        print(f"\nRozpoczynanie rozwiązania dla {self.Rounds} rund DES...")
        print(f"Limit czasu: {time_limit} sekund")

        # Ustawienie solvera (CBC jest domyślny w PuLP)
        self.problem.solve()

        print(f"\nStatus rozwiązania: {LpStatus[self.problem.status]}")
        print(f"Wartość funkcji celu: {self.problem.objective.value()}")

        return self.problem.status

    def get_solution(self):
        """Pobiera i formatuje rozwiązanie"""
        if self.problem.status != 1:  # 1 = Optimal
            print("Brak rozwiązania optymalnego")
            return None

        solution = {
            'input_diff': self._get_state_diff(0),
            'output_diff': self._get_state_diff(self.Rounds),
            'round_diffs': [self._get_state_diff(r) for r in range(self.Rounds + 1)],
            'objective_value': self.problem.objective.value(),
            'transitions': self._get_selected_transitions()
        }

        return solution

    def _get_state_diff(self, r):
        """Konwertuje zmienne stanu na liczbę hex"""
        l_bits = [int(self.L[(r, b)].varValue) for b in range(32)]
        r_bits = [int(self.R[(r, b)].varValue) for b in range(32)]

        l_val = sum(bit << (31 - i) for i, bit in enumerate(l_bits))
        r_val = sum(bit << (31 - i) for i, bit in enumerate(r_bits))

        return hex(l_val), hex(r_val)

    def _get_selected_transitions(self):
        """Pobiera wybrane przejścia S-boksów"""
        selected = []

        for r in range(1, self.Rounds + 1):
            for i in range(8):
                for t_idx in range(len(self.transitions[i])):
                    if self.T[(r, i, t_idx)].varValue > 0.5:  # Wartość ~1
                        trans = self.transitions[i][t_idx].copy()
                        trans['round'] = r
                        trans['sbox'] = i
                        selected.append(trans)

        return selected

    def print_solution(self):
        """Wypisuje rozwiązanie w czytelnej formie"""
        solution = self.get_solution()
        if not solution:
            return

        print("\n" + "=" * 60)
        print("CHARAKTERYSTYKA RÓŻNICOWA DLA DES")
        print("=" * 60)

        print(f"\nLiczba rund: {self.Rounds}")
        print(f"Koszt całkowity: {solution['objective_value']}")
        print(f"Szacowane prawdopodobieństwo: 2^-{solution['objective_value'] / 1000:.2f}")

        print(f"\nRóżnica wejściowa (plaintext):")
        print(f"  L0: {solution['input_diff'][0]}")
        print(f"  R0: {solution['input_diff'][1]}")

        print(f"\nRóżnica wyjściowa (ciphertext):")
        print(f"  L{self.Rounds}: {solution['output_diff'][0]}")
        print(f"  R{self.Rounds}: {solution['output_diff'][1]}")

        print(f"\nPrzejścia S-boksów:")
        for trans in solution['transitions']:
            print(f"  Runda {trans['round']}, S{trans['sbox'] + 1}: "
                  f"Δ_in=0x{trans['delta_in']:02x}→Δ_out=0x{trans['delta_out']:x}, "
                  f"waga={trans['weight']}, p={trans['probability']}")

        print(f"\nRóżnice po każdej rundzie:")
        for r, (l_val, r_val) in enumerate(solution['round_diffs']):
            print(f"  Runda {r}: L={l_val}, R={r_val}")

