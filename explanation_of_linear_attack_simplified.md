# Wyjaśnienie Ataku Liniowego (Wersja Uproszczona)

Poniżej znajduje się proste wyjaśnienie "na chłopski rozum", co robią poszczególne pliki i co oznaczają wyniki w konsoli.

## 1. Co robią pliki?

### 💀 `des_milp_solver.py` (Mózg operacji)
Ten plik to **planista**. Nie atakuje szyfru bezpośrednio. Używa zaawansowanej matematyki (programowanie liniowe), żeby znaleźć "dziurę" w strukturze szyfru DES.
*   **Co robi:** Szuka takiej kombinacji bitów wejściowych i wyjściowych (masek), która po przejściu przez szyfr **nie jest losowa**.
*   **Analogi:** To tak, jakbyś szukał w kasynie ruletki, która jest lekko krzywa. Solver mówi Ci: *"Jeśli postawisz na te konkretne numery, będziesz wygrywał o 1% częściej niż inni"*.

### ⚔️ `linear_attack.py` (Wykonawca)
Ten plik to **włamywacz**. Bierze plan przygotowany przez Solvera i wykonuje brudną robotę.
*   **Co robi:**
    1. Generuje tysiące par (Tekst Jawny, Szyfrogram).
    2. Dla każdej pary "cofa" ostatnią rundę szyfrowania, zgadując kawałek klucza.
    3. Sprawdza, czy dla zgadniętego klucza równanie (to z Solvera) jest spełnione.
*   **Analogi:** Bierze tysiące wyników z tej krzywej ruletki i sprawdza, kto przy stole oszukuje (czyli jaki jest klucz), patrząc na wyniki.

---

## 2. Co oznacza tekst w konsoli? (Linijka po linijce)

```text
Running Linear Attack with 20000 samples...
```
Zaczynamy atak. Bierzemy 20,000 próbek (par tekst jawny-szyfrogram), żeby mieć wystarczająco dużo danych do statystyki.

```text
MILP Status: Optimal
Active S-boxes count: 1.0
```
Solver skończył pracę. "Optimal" oznacza, że znalazł **najlepszą możliwą** dziurę w szyfrze. "Active S-boxes count: 1.0" oznacza, że atak jest bardzo tani – musimy złamać tylko **jeden** S-box (mały kawałek szyfru), żeby odzyskać część klucza.

```text
Characteristic found.
Gamma_P (L0, R0) = (0x4010000, 0x200000)
Gamma_L2 = 0x4010000
```
To są konkrety znalezionej dziury (maski bitowe). To instrukcja dla ataku: *"Patrz na bit nr X tekstu jawnego i bit nr Y szyfrogramu"*.

```text
Active S-boxes in Round 3: [2]
S-box Output Masks (before P): {2: 5}
```
Kluczowa informacja. Musimy zaatakować tylko **S-box numer 2** w trzeciej rundzie. Reszta nas nie obchodzi. To drastycznie przyspiesza atak.

```text
Generating Plantext-Ciphertext pairs...
True Key: 0xdd933ba5999d81c
True Subkeys for active S-boxes: {2: 35}
```
Tutaj skrypt generuje dane do ataku. Wypisuje też **prawdziwy klucz** (i ten fragment klucza, którego szukamy: `35`), żebyśmy na końcu wiedzieli, czy nam się udało. W prawdziwym ataku tego byś nie widział.

```text
Testing 64 key candidates...
```
Zaczynamy zgadywanie. Ponieważ atakujemy tylko jeden S-box (S2), mamy tylko $2^6 = 64$ możliwe kombinacje klucza dla tego fragmentu. To błyskawiczne do sprawdzenia.

```text
Best Key Found: {2: 35}
Max Bias: 583.0
```
**Mamy zwycięzcę!**
*   **Best Key Found: {2: 35}**: Skrypt twierdzi, że fragment klucza to `35`. Patrząc wyżej ("True Subkeys") – **zgadza się idealnie!**
*   **Max Bias: 583.0**: To jest miara pewności. Oznacza, że ten klucz "pasował" o 583 razy częściej (lub rzadziej) niż wynosi średnia dla losowego szumu. To bardzo mocny sygnał. Inne (błędne) klucze miałyby bias bliski 0.

```text
SUCCESS: Key bits recovered successfully!
```
Potwierdzenie sukcesu. Matematyka zadziałała, fragment klucza został wykradziony.
