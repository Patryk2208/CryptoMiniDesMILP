# Dokumentacja Projektu CryptoMiniDesMILP

## Przegląd Projektu

Projekt implementuje **metody określania odporności szyfrów blokowych na ataki różnicowy i liniowy** z wykorzystaniem **Mieszanego Programowania Liniowego Całkowitoliczbowego (MILP)**. Implementacja oparta jest na opisie teoretycznym algorytmu DES oraz metod kryptoanalizy przedstawionych w dokumentacji projektowej.

---

## Struktura Plików

```
CryptoMiniDesMILP/
├── full_des.py               # Implementacja algorytmu DES
├── sbox_tables.py            # Tablice DDT i LAT dla S-boxów
├── des_milp_diff_solver.py   # Solver MILP dla ataku różnicowego
├── des_milp_solver.py        # Solver MILP dla ataku liniowego
├── differential_attack.py    # Implementacja ataku różnicowego
└── linear_attack.py          # Implementacja ataku liniowego
```

---

## Szczegółowy Opis Plików

### 1. `full_des.py` — Implementacja Algorytmu DES

**Odniesienie:** Sekcja 1 dokumentacji (Algorytm DES)

Plik zawiera pełną implementację algorytmu Data Encryption Standard zgodnie ze specyfikacją dokumentacji. Klasa `DES` realizuje następujące elementy:

#### Tablice Permutacji
Zgodnie z Sekcją 1.2 dokumentacji, algorytm wykorzystuje szereg tablic permutacji:
- **`IP_TABLE`** — Permutacja Początkowa (Tabela 4 w dokumentacji). Blok 64-bitowy jest poddawany tej permutacji na początku szyfrowania.
- **`FP_TABLE`** — Permutacja Końcowa IP⁻¹ (Tabela 5). Stosowana po zakończeniu 16 rund.
- **`E_TABLE`** — Permutacja z Rozszerzeniem (Tabela 6). Rozszerza 32-bitową prawą połowę do 48 bitów.
- **`P_TABLE`** — Permutacja P-bloku (Tabela 7). Stosowana po przejściu przez S-boxy.

#### Generowanie Podkluczy
Zgodnie z Sekcją 1.1 dokumentacji:
- **`PC1_TABLE`** — Permutacja Wejściowa Klucza (Tabela 1). Redukuje 64-bitowy klucz do 56 bitów poprzez pominięcie bitów parzystości.
- **`PC2_TABLE`** — Permutacja Kompresji (Tabela 3). Z 56 bitów wybiera 48 bitów dla klucza rundy.
- **`SHIFT_TABLE`** — Przesunięcie Połówek (Tabela 2). Określa liczbę bitów przesunięcia dla każdej rundy.

#### S-boxy
Zgodnie z Sekcją 1.4 dokumentacji, **`S_BOXES`** zawiera 8 tablic S-boxów (Tabela 8). Każdy S-box przyjmuje 6-bitowe wejście i zwraca 4-bitowe wyjście. Bity 1 i 6 określają wiersz, a bity 2-5 określają kolumnę.

#### Główne Metody
- **`generate_keys()`** — Implementuje algorytm generowania podkluczy zgodnie z Sekcją 1.1.
- **`f_function()`** — Realizuje funkcję f opisaną w Sekcji 1.3: ekspansja E, XOR z kluczem, przejście przez S-boxy, permutacja P.
- **`run_feistel()`** — Implementuje strukturę Feistela (Sekcja 1.5): L_i = R_{i-1}, R_i = L_{i-1} ⊕ f(R_{i-1}, K_i).

---

### 2. `sbox_tables.py` — Tablice DDT i LAT

**Odniesienie:** Sekcje 6.2.2 i 7.2.2 dokumentacji

Plik implementuje tablice niezbędne do analizy kryptograficznej S-boxów:

#### DDT (Tablica Rozkładu Różnic)
Zgodnie z Sekcją 6.2.2 dokumentacji, DDT służy do modelowania warstwy nieliniowej w ataku różnicowym. Dla każdego S-boxa oblicza się:

```
DDT[Δin][Δout] = |{x : S(x) ⊕ S(x ⊕ Δin) = Δout}|
```

Prawdopodobieństwo przejścia różnicowego P[ΔX → ΔY] = DDT[ΔX][ΔY] / 2^n. Zbiór wszystkich przejść o niezerowym prawdopodobieństwie tworzy podstawę do weryfikacji poprawności ścieżek różnicowych.

#### LAT (Tablica Aproksymacji Liniowych)
Zgodnie z Sekcją 7.2.2 dokumentacji, LAT służy do modelowania S-boxów w ataku liniowym:

```
LAT[α][β] = |{x : α·x = β·S(x)}| - 2^(n-1)
```

gdzie α i β to maski wejściowe i wyjściowe, a operacja · oznacza iloczyn skalarny bitów (parzystość koniunkcji). Wartość LAT reprezentuje obciążenie (bias) od prawdopodobieństwa 50%.

#### Funkcje Pomocnicze
- **`compute_ddt()`** — Oblicza tablicę DDT dla pojedynczego S-boxa.
- **`compute_lat()`** — Oblicza tablicę LAT dla pojedynczego S-boxa.
- **`max_differential_probability()`** — Znajduje najlepsze przejście różnicowe.
- **`max_linear_bias()`** — Znajduje najlepszą aproksymację liniową.

Tablice **`DDT_TABLES`** i **`LAT_TABLES`** są wstępnie obliczone dla wszystkich 8 S-boxów DES.

---

### 3. `des_milp_diff_solver.py` — Solver MILP dla Ataku Różnicowego

**Odniesienie:** Sekcja 6 dokumentacji (Atak różnicowy z wykorzystaniem MILP)

Plik implementuje algorytm wyszukiwania optymalnej charakterystyki różnicowej przy użyciu MILP.

#### Porównanie z Podejściem Klasycznym (Sekcja 6.1)
Zgodnie z dokumentacją, podejście klasyczne wymaga ręcznej weryfikacji propagacji różnic i często ogranicza się do optimów lokalnych. MILP pozwala na automatyczne przeszukiwanie przestrzeni rozwiązań z gwarancją znalezienia globalnego optimum.

#### Modelowanie XOR (Sekcja 6.2.1, Równanie 1)
Operacja XOR w domenie różnicowej jest modelowana przy użyciu zmiennej pomocniczej d:
```
a + b + c ≥ 2d
d ≤ a, d ≤ b, d ≤ c  
a + b + c ≤ 2
```
Ten układ nierówności zapewnia, że różnica nie może powstać ani zniknąć w sposób niezgodny z arytmetyką F₂.

#### Aktywność S-boxów (Sekcja 6.3)
Zgodnie z dokumentacją, S-box jest **aktywny** gdy wektor różnic wejściowych jest niezerowy. S-box **pasywny** ma zerowy wektor wejściowy i wyjściowy z prawdopodobieństwem 1.

#### Funkcja Celu (Równanie 2)
```
Minimalizuj: Σ A_{r,k}
```
gdzie A_{r,k} to zmienna binarna oznaczająca aktywność k-tego S-boxa w r-tej rundzie. Minimalizacja liczby aktywnych S-boxów maksymalizuje prawdopodobieństwo charakterystyki.

---

### 4. `des_milp_solver.py` — Solver MILP dla Ataku Liniowego

**Odniesienie:** Sekcja 7 dokumentacji (Atak liniowy z wykorzystaniem MILP)

Plik implementuje algorytm wyszukiwania optymalnej aproksymacji liniowej przy użyciu MILP.

#### Dualność z Atakiem Różnicowym (Sekcja 7.2.1)
Dokumentacja podkreśla fundamentalną zasadę dualności: ograniczenia dla operacji XOR i rozgałęzień zamieniają się rolami między atakiem różnicowym a liniowym.

#### Modelowanie XOR (Równanie 3)
W ataku liniowym maski na wszystkich wejściach i wyjściu operacji XOR muszą być identyczne:
```
a = b = c
```
Jest to przeciwieństwo do ataku różnicowego, gdzie stosuje się nierówności.

#### Modelowanie Rozgałęzień (Równanie 4)
Gdy sygnał rozdziela się na dwie ścieżki (np. w permutacji rozszerzającej E), maska wejściowa jest sumą modulo 2 masek wyjściowych:
```
a + b + c ≥ 2d
d ≤ a, d ≤ b, d ≤ c
a + b + c ≤ 2
```
Jest to analogiczne do modelowania XOR w ataku różnicowym.

#### Funkcja Celu (Równanie 5)
Identyczna jak w ataku różnicowym — minimalizacja liczby aktywnych S-boxów. Zgodnie z Lematem o Nawarstwianiu (Piling-up Lemma), całkowite odchylenie maleje wykładniczo wraz z liczbą aktywnych S-boxów.

---

### 5. `differential_attack.py` — Implementacja Ataku Różnicowego

**Odniesienie:** Sekcje 2 i 6.4 dokumentacji

Plik implementuje pełny atak różnicowy z wykorzystaniem charakterystyki obliczonej przez MILP.

#### Koncepcja Ataku (Sekcja 2.1)
Zgodnie z dokumentacją, kluczową ideą jest znajdowanie charakterystyki różnicowej — zestawu różnic ΔP ⊕ ΔP' oraz ΔC ⊕ ΔC' gdzie przekształcenie par tekstów jest bardziej prawdopodobne niż dla innych różnic.

#### Proces Ataku (Sekcja 6.4)
Implementacja realizuje algorytm zgodnie z opisem w dokumentacji:

1. **Gromadzenie par** — Generowanie M par tekstów jawnych o różnicy Δin (obliczonej przez MILP) i uzyskanie ich szyfrogramów.

2. **Ekstrakcja klucza metodą zliczania** — Dla każdego S-boxa testowane są wszystkie 64 możliwe wartości 6-bitowego podklucza. Wykonuje się częściowe odszyfrowanie i weryfikuje zgodność różnicy przed ostatnim S-boxem.

3. **Wybór kandydata** — Kandydat osiągający najwyższy wynik w liczniku zgodności jest uznawany za poprawny fragment klucza.

#### Struktura Klasy
- **`undo_ip()`** — Cofa permutację końcową IP⁻¹ aby uzyskać stan przed nią.
- **`get_sbox_output_diff()`** — Symuluje przejście przez S-box dla danej hipotezy klucza.
- **`run_attack()`** — Przeprowadza pełny atak metodą zliczania.

---

### 6. `linear_attack.py` — Implementacja Ataku Liniowego

**Odniesienie:** Sekcje 3 i 7.4 dokumentacji

Plik implementuje atak kryptoanalizy liniowej z integracją solvera MILP.

#### Koncepcja Ataku (Sekcja 3.1)
Zgodnie z dokumentacją, atak liniowy opiera się na wyszukiwaniu liniowych zależności pomiędzy bitami tekstu jawnego, szyfrogramu oraz klucza, które zachodzą z prawdopodobieństwem różnym od 1/2 (istnienie biasu statystycznego).

#### Aproksymacja Liniowa (Sekcja 3.2)
Równanie liniowe ma postać:
```
⊕_i P[i] ⊕ ⊕_j C[j] = ⊕_k K[k]
```
z prawdopodobieństwem P = 1/2 + ε, gdzie ε to bias.

#### Proces Ataku (Sekcja 7.4)
1. **Gromadzenie danych** — Pozyskanie dużej liczby N par (P, C). Liczba N jest odwrotnie proporcjonalna do kwadratu biasu (ε⁻²).

2. **Testowanie podkluczy** — Dla każdej pary testowane są wszystkie możliwe podklucze ostatniej rundy. Szyfrogram jest częściowo odszyfrowywany.

3. **Statystyka** — Zliczanie ile razy równanie liniowe jest spełnione. Kandydat z największym odchyleniem od N/2 jest typowany jako poprawny.

#### Integracja z MILP
Plik integruje się z `des_milp_solver.py` aby automatycznie obliczać optymalne maski wejściowe i wyjściowe zamiast używać ręcznie zdefiniowanych wartości.

---

## Zależności Między Plikami

```
full_des.py ─────────────────────────────────────┐
     │                                            │
     ▼                                            │
sbox_tables.py ──────────────────────────────────┤
     │                                            │
     ├──────────────────┐                         │
     ▼                  ▼                         │
des_milp_diff_solver.py    des_milp_solver.py    │
     │                        │                   │
     ▼                        ▼                   │
differential_attack.py    linear_attack.py ◄─────┘
```

Wszystkie pliki atakowe importują `full_des.py` dla operacji szyfrowania. Solvery MILP korzystają z tablic DDT/LAT z `sbox_tables.py`. Pliki ataków integrują odpowiednie solvery MILP.
