"""
Moduł Tablic S-Box dla Kryptoanalizy DES
=========================================
Implementuje DDT (Tablicę Rozkładu Różnic) i LAT (Tablicę Aproksymacji Liniowych)
zgodnie z opisem w Sekcjach 6.2.2 i 7.2.2 dokumentacji.

Odniesienia:
- DDT: Używana w kryptoanalizie różnicowej do znajdowania poprawnych przejść różnicowych
- LAT: Używana w kryptoanalizie liniowej do znajdowania obciążonych aproksymacji liniowych
"""

from full_des import DES


def compute_ddt(sbox):
    """
    Oblicza Tablicę Rozkładu Różnic dla S-boxa 6->4 bity.
    
    DDT[Δin][Δout] = liczba wejść x dla których S(x) ⊕ S(x ⊕ Δin) = Δout
    
    Zgodnie z Sekcją 6.2.2 (wzór na prawdopodobieństwo DDT):
    P[ΔX → ΔY] = |{x : S(x) ⊕ S(x ⊕ ΔX) = ΔY}| / 2^n
    
    Argumenty:
        sbox: Lista 4 wierszy, każdy z 16 kolumnami (standardowy format S-boxa DES)
    
    Zwraca:
        Tablicę 64x16 gdzie DDT[i][j] = liczba przejść z różnicy wejściowej i do różnicy wyjściowej j
    """
    ddt = [[0] * 16 for _ in range(64)]
    
    for x in range(64):
        # Konwertuj 6-bitowe wejście na format wiersz/kolumna dla S-boxa
        row_x = ((x >> 5) & 1) * 2 + (x & 1)
        col_x = (x >> 1) & 0x0F
        sbox_x = sbox[row_x][col_x]
        
        for delta_in in range(64):
            x_prime = x ^ delta_in
            row_x_prime = ((x_prime >> 5) & 1) * 2 + (x_prime & 1)
            col_x_prime = (x_prime >> 1) & 0x0F
            sbox_x_prime = sbox[row_x_prime][col_x_prime]
            
            delta_out = sbox_x ^ sbox_x_prime
            ddt[delta_in][delta_out] += 1
    
    return ddt


def compute_lat(sbox):
    """
    Oblicza Tablicę Aproksymacji Liniowych dla S-boxa 6->4 bity.
    
    LAT[α][β] = |{x : α·x = β·S(x)}| - 2^(n-1)
    
    Zgodnie z Sekcją 7.2.2 (definicja LAT w ataku liniowym):
    Wartość reprezentuje obciążenie (bias) od prawdopodobieństwa 50% aproksymacji liniowej.
    
    Argumenty:
        sbox: Lista 4 wierszy, każdy z 16 kolumnami (standardowy format S-boxa DES)
    
    Zwraca:
        Tablicę 64x16 gdzie LAT[α][β] = wartość obciążenia dla maski wejściowej α i maski wyjściowej β
    """
    lat = [[0] * 16 for _ in range(64)]
    
    for alpha in range(64):  # Maska wejściowa (6 bitów)
        for beta in range(16):  # Maska wyjściowa (4 bity)
            count = 0
            for x in range(64):
                # Oblicz wyjście S-boxa
                row = ((x >> 5) & 1) * 2 + (x & 1)
                col = (x >> 1) & 0x0F
                s_out = sbox[row][col]
                
                # Parzystość (α · x) = XOR bitów gdzie alpha ma jedynki
                parity_in = bin(alpha & x).count('1') % 2
                # Parzystość (β · S(x))
                parity_out = bin(beta & s_out).count('1') % 2
                
                if parity_in == parity_out:
                    count += 1
            
            # Wartość LAT = count - 32 (obciążenie od 50%)
            lat[alpha][beta] = count - 32
    
    return lat


def get_valid_differential_transitions(ddt, min_probability=0):
    """
    Pobiera wszystkie poprawne (o niezerowym prawdopodobieństwie) przejścia różnicowe z DDT.
    
    Argumenty:
        ddt: Tablica Rozkładu Różnic 64x16
        min_probability: Minimalny próg liczności (0 = wszystkie niezerowe)
    
    Zwraca:
        Listę krotek (delta_in, delta_out, count)
    """
    transitions = []
    for d_in in range(64):
        for d_out in range(16):
            if ddt[d_in][d_out] > min_probability:
                transitions.append((d_in, d_out, ddt[d_in][d_out]))
    return transitions


def get_best_linear_approximations(lat, min_bias=0):
    """
    Pobiera najlepsze (o największym bezwzględnym obciążeniu) aproksymacje liniowe z LAT.
    
    Argumenty:
        lat: Tablica Aproksymacji Liniowych 64x16
        min_bias: Minimalny próg bezwzględnego obciążenia
    
    Zwraca:
        Listę krotek (maska_wej, maska_wyj, obciążenie) posortowaną według |obciążenia|
    """
    approximations = []
    for alpha in range(64):
        for beta in range(16):
            bias = lat[alpha][beta]
            if abs(bias) > min_bias:
                approximations.append((alpha, beta, bias))
    
    # Sortuj według bezwzględnego obciążenia (malejąco)
    approximations.sort(key=lambda x: abs(x[2]), reverse=True)
    return approximations


def max_differential_probability(ddt):
    """
    Pobiera maksymalne prawdopodobieństwo różnicowe dla S-boxa (z wykluczeniem trywialnego Δ=0→0).
    
    Zwraca:
        Krotkę (delta_in, delta_out, prawdopodobieństwo) dla najlepszego nietrywialnego różnicowego
    """
    best = (0, 0, 0)
    for d_in in range(1, 64):  # Pomiń 0 (trywialny)
        for d_out in range(16):
            if ddt[d_in][d_out] > best[2]:
                best = (d_in, d_out, ddt[d_in][d_out])
    
    # Prawdopodobieństwo = count / 64 (ponieważ 64 możliwych wejść)
    prob = best[2] / 64.0
    return best[0], best[1], prob


def max_linear_bias(lat):
    """
    Pobiera maksymalne obciążenie liniowe dla S-boxa (z wykluczeniem trywialnego α=0, β=0).
    
    Zwraca:
        Krotkę (maska_wej, maska_wyj, obciążenie) dla najlepszej nietrywialnej aproksymacji
    """
    best = (0, 0, 0)
    for alpha in range(1, 64):  # Pomiń 0
        for beta in range(1, 16):  # Pomiń 0
            if abs(lat[alpha][beta]) > abs(best[2]):
                best = (alpha, beta, lat[alpha][beta])
    
    return best


# Wstępnie oblicz tablice dla wszystkich 8 S-boxów DES
DDT_TABLES = [compute_ddt(sbox) for sbox in DES.S_BOXES]
LAT_TABLES = [compute_lat(sbox) for sbox in DES.S_BOXES]


if __name__ == "__main__":
    print("=== Analiza S-Boxów dla Kryptoanalizy DES ===\n")
    
    for i in range(8):
        d_in, d_out, prob = max_differential_probability(DDT_TABLES[i])
        a_in, a_out, bias = max_linear_bias(LAT_TABLES[i])
        
        print(f"S{i+1}:")
        print(f"  Najlepsze różnicowe: Δin={d_in:02x} -> Δout={d_out:x}, prawd.={prob:.4f}")
        print(f"  Najlepsza aproksy. liniowa: α={a_in:02x}, β={a_out:x}, bias={bias}/32 = {abs(bias)/32:.4f}")
        print()
