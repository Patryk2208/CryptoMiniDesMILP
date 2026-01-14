**Perfekcyjnie! Oto plan implementacji podzielony na logiczne fazy:**

## **FAZA 0: PRZYGOTOWANIE DANYCH (Offline, raz)**

### **Krok 0.1: Załaduj definicję DES**
- Zdefiniuj permutacje: IP, IP⁻¹, E, P, PC1, PC2 (te ostatnie tylko jeśli modelujesz klucz)
- Zdefiniuj S-boksy S1..S8 jako tablice 64×4 (wartości 0-15)

### **Krok 0.2: Wygeneruj DDT dla każdego S-boksu**
Dla każdego S-boksa S_i (i=1..8):
- Stwórz tablicę `ddt[i][Δ_in][Δ_out]` rozmiaru 64×16
- Dla każdej pary 6-bitowych wejść (x, x') gdzie Δ_in = x ⊕ x':
  - Oblicz y = S_i(x), y' = S_i(x')
  - Δ_out = y ⊕ y'
  - Zwiększ `ddt[i][Δ_in][Δ_out]` o 1
- Normalizuj do prawdopodobieństw: `p = ddt[i][Δ_in][Δ_out] / 64`

### **Krok 0.3: Oblicz wagi dla każdego przejścia**
Dla każdego S-boksa i, każdego Δ_in (0..63), każdego Δ_out (0..15):
- Jeśli `p > 0`: `weight = -log2(p)` (zaokrąglij do np. 3 miejsc po przecinku × 1000)
- Jeśli `p = 0`: `weight = INF` (duża liczba, np. 10^6)

### **Krok 0.4: Przygotuj tablicę możliwych przejść**
Dla każdego S-boksa i:
- Stwórz listę `transitions[i]` wszystkich par `(Δ_in, Δ_out)` gdzie `p > 0`
- Dla każdego przejścia zapisz: `(Δ_in, Δ_out, weight, probability)`

---

## **FAZA 1: BUDOWA MODELU MILP**

### **Krok 1.1: Zdefiniuj parametry modelu**
- `R` = liczba rund (zacznij od 3-4 dla testów)
- `input_diff` = zadana różnica wejściowa (np. `0x40000000 0x04000000`)
- `output_diff` = opcjonalnie: różnica wyjściowa (jeśli szukasz konkretnej)

### **Krok 1.2: Stwórz zmienne stanu**
Dla każdej rundy `r = 0..R`:
- `L_r[0..31]` - 32 zmienne binarne (różnica lewej połowy)
- `R_r[0..31]` - 32 zmienne binarne (różnica prawej połowy)

### **Krok 1.3: Stwórz zmienne dla wyboru przejść S-boksów**
Dla każdej rundy `r = 1..R` i każdego S-boksa `i = 1..8`:
- Dla każdego możliwego przejścia `t` w `transitions[i]`:
  - Stwórz zmienną binarną `s_{r,i,t}` = 1 jeśli wybrano to przejście
- Dodaj ograniczenie: `sum_{t} s_{r,i,t} = 1` (wybrano dokładnie jedno przejście)

### **Krok 1.4: Ustal różnicę początkową**
Dla każdego bitu `j = 0..31`:
- Ustaw `L_0[j]` zgodnie z zadanym `input_diff.left[j]`
- Ustaw `R_0[j]` zgodnie z zadanym `input_diff.right[j]`

---

## **FAZA 2: MODELOWANIE RUNDY DES**

### **Krok 2.1: Modelowanie rozszerzenia E**
Dla rundy `r`:
- Stwórz pomocnicze zmienne `E_in_{r}[0..47]` (48 bitów)
- Dla każdego bitu `j = 0..47`:
  - Określ który bit `R_{r-1}[k]` jest kopiowany przez E
  - Dodaj ograniczenie: `E_in_{r}[j] = R_{r-1}[k]`

### **Krok 2.2: Modelowanie S-boksów**
Dla każdego S-boksa `i = 1..8` w rundzie `r`:

1. **Wejście S-boksa:**
   - `S_in_{r,i}[0..5]` = 6 bitów z `E_in_{r}` (zgodnie z definicją DES)

2. **Implikacje dla każdego przejścia t = (Δ_in, Δ_out):**
   - Jeśli `s_{r,i,t} = 1`, to:
     - Dla każdego bitu `k = 0..5`: `S_in_{r,i}[k] = bit_k(Δ_in)`
     - Stwórz zmienne `S_out_{r,i}[0..3]`
     - Dla każdego bitu `m = 0..3`: `S_out_{r,i}[m] = bit_m(Δ_out)`
   
   Implementacja przez "big-M":
   ```
   Dla każdego bitu k:
     S_in[k] ≤ bit_k(Δ_in) + M*(1 - s_t)
     S_in[k] ≥ bit_k(Δ_in) - M*(1 - s_t)
   ```

### **Krok 2.3: Modelowanie permutacji P**
- Stwórz zmienne `F_out_{r}[0..31]` (wyjście funkcji F)
- Dla każdego bitu `j = 0..31`:
  - Określ który bit którego S_out odpowiada (zgodnie z P)
  - Dodaj ograniczenie: `F_out_{r}[j] = S_out_{r,i}[k]`

---

## **FAZA 3: MODELOWANIE STRUKTURY FEISTELA**

### **Krok 3.1: Propagacja lewej połowy**
Dla każdej rundy `r = 1..R` i każdego bitu `j = 0..31`:
- `L_r[j] = R_{r-1}[j]`

### **Krok 3.2: Propagacja prawej połowy z XOR**
Dla każdej rundy `r = 1..R` i każdego bitu `j = 0..31`:
- `R_r[j] = L_{r-1}[j] XOR F_out_{r}[j]`
  
**Linearizacja XOR:**
```
x = y XOR z  →  
  x ≤ y + z
  x ≥ y - z
  x ≥ z - y
  x ≤ 2 - y - z
```

---

## **FAZA 4: FUNKCJA CELU I OPCJONALNE OGRANICZENIA**

### **Krok 4.1: Zdefiniuj funkcję celu**
- `total_weight = sum_{r,i,t} (weight_t * s_{r,i,t})`
- Ustaw cel: `minimize(total_weight)`

### **Krok 4.2: Opcjonalnie - ustal różnicę wyjściową**
Jeśli szukasz konkretnej charakterystyki:
- Dla każdego bitu `j = 0..31`:
  - Ustaw `L_R[j]` zgodnie z zadanym `output_diff.left[j]`
  - Ustaw `R_R[j]` zgodnie z zadanym `output_diff.right[j]`

### **Krok 4.3: Opcjonalnie - ogranicz liczbę aktywnych S-boksów**
Możesz dodać dla testów:
- `sum_{r,i} (1 - s_{r,i,zerowe}) ≤ max_active` (gdzie `zerowe` to przejście (0,0))

---