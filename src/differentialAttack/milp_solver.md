KATEGORIE ZMIENNYCH:
1. ZMIENNE STANU (STATE VARIABLES)

Reprezentują różnice bitowe w danych.
L_r[b] - Left half difference bit

    Typ: Binary (0/1)

    Indeksy: r = 0..R (runda), b = 0..31 (bit)

    Rozmiar: (R+1) × 32 zmiennych

    Znaczenie: Bit b różnicy lewej połowy po rundzie r

    Przykład: L_2[15] = 1 oznacza, że bit 15 lewej połowy po 2 rundzie ma różnicę 1

R_r[b] - Right half difference bit

    Typ: Binary (0/1)

    Indeksy: r = 0..R, b = 0..31

    Rozmiar: (R+1) × 32 zmiennych

    Znaczenie: Bit b różnicy prawej połowy po rundzie r

    Razem z L_r: Para (L_r, R_r) to pełna 64-bitowa różnica stanu po rundzie r

2. ZMIENNE FUNKCJI F (F-FUNCTION VARIABLES)
E_r[e] - Expanded input to S-boxes

    Typ: Binary (0/1)

    Indeksy: r = 1..R (runda), e = 0..47 (bit expansion)

    Rozmiar: R × 48 zmiennych

    Znaczenie: Bit e po rozszerzeniu E prawej połowy z rundy r-1

    Obliczenie: E_r = E(R_{r-1}) gdzie E to funkcja rozszerzenia DES

    Uwaga: To zmienne POMOCNICZE - można je wyeliminować, ale ułatwiają zrozumienie

F_r[b] - Output of F-function

    Typ: Binary (0/1)

    Indeksy: r = 1..R, b = 0..31

    Rozmiar: R × 32 zmiennych

    Znaczenie: Bit b różnicy na wyjściu funkcji F w rundzie r

    Obliczenie: F_r = P(S-box_outputs) gdzie P to permutacja

3. ZMIENNE S-BOKSÓW (S-BOX VARIABLES)
S_in_{r,i}[k] - Input to S-box

    Typ: Binary (0/1)

    Indeksy: r = 1..R, i = 1..8 (numer S-boksa), k = 0..5 (bit wejścia)

    Rozmiar: R × 8 × 6 = 48R zmiennych

    Znaczenie: Bit k różnicy wejściowej do S-boksa i w rundzie r

    Powiązanie: S_in_{r,i} to 6-bitowy wycinek z E_r

S_out_{r,i}[m] - Output from S-box

    Typ: Binary (0/1)

    Indeksy: r = 1..R, i = 1..8, m = 0..3 (bit wyjścia)

    Rozmiar: R × 8 × 4 = 32R zmiennych

    Znaczenie: Bit m różnicy wyjściowej z S-boksa i w rundzie r

4. ZMIENNE WYBORU PRZEJŚĆ (TRANSITION SELECTION VARIABLES)

NAJWAŻNIEJSZE dla metody z wagami!
T_{r,i,t} - Transition selection

    Typ: Binary (0/1)

    Indeksy:

        r = 1..R (runda)

        i = 1..8 (S-boks)

        t ∈ T_i gdzie T_i to zbiór możliwych przejść dla S-boksa i

    Rozmiar: R × Σ_{i=1..8} |T_i| gdzie typowo |T_i| ≈ 150-200

        Dla 8 rund: 8 × 8 × 180 ≈ 11,520 zmiennych

    Znaczenie:

        T_{r,i,t} = 1 jeśli w rundzie r, S-boks i używa przejścia t

        t to para (Δ_in, Δ_out, weight)

    Ograniczenie: Σ_{t∈T_i} T_{r,i,t} = 1 (dokładnie jedno przejście na S-boks)

Przykład struktury t:

Dla S-boksa 1, przejście może być:
python

t = {
    'delta_in': 0x02,    # 6-bitowa różnica wejściowa: 000010
    'delta_out': 0x05,   # 4-bitowa różnica wyjściowa: 0101
    'weight': 3000,      # -log2(p) × 1000, gdzie p = 8/64 = 1/8
    'probability': 0.125 # 1/8
}

5. ZMIENNE POMOCNICZE DLA LINEARIZACJI
xor_{r,b} - XOR linearization helper

    Typ: Binary (0/1) LUB Continuous [0,1] z całkowitoliczbowymi warunkami

    Indeksy: r = 1..R, b = 0..31

    Rozmiar: R × 32 zmiennych

    Znaczenie: Pomocnicze zmienne do reprezentacji x = y XOR z

    Użycie: Gdy mamy R_r[b] = L_{r-1}[b] XOR F_r[b], potrzebujemy zmiennych pomocniczych do linearizacji

Alternatywnie: Można linearizować bez dodatkowych zmiennych przez 4 nierówności.