import sys

# Importujemy funkcjonalności z sąsiednich pakietów
from des import DES
from differentialAttack.attack import DifferentialAttackDES
from src.differentialAttack.milp_probability_solver import DES_MILP_Solver
from collections import Counter
from matplotlib import pyplot as plt

def main():
    print("=== CryptoMiniDesMILP: DES Differential Attack ===\n")
    
    # # 1. Uruchomienie MILP (dla celów informacyjnych szukamy charakterystyki dla 5 rund)
    # print("KROK 1: Szukanie charakterystyki metodą MILP (dla 5 rund)...")
    # active_sboxes = find_best_characteristic(rounds=5)
    # for r, sboxes in active_sboxes.items():
    #     print(f"  Runda {r+1}: Aktywne S-boxy {sboxes}")
    #
    # print("\n" + "-"*50 + "\n")
    #
    # # 2. Uruchomienie Ataku
    # print("KROK 2: Próba odzyskania klucza dla 6 RUND...")
    #
    # # Ustalamy sekretny klucz
    # secret_key = 0x133457799BBDDFF1
    #
    # # Uruchamiamy atak na 6 rund
    # # Zwiększamy liczbę par, ponieważ atak na 6 rund wymaga więcej danych niż na 4
    # success = run_attack(target_rounds=6, real_key=secret_key, pairs_count=10000)
    #
    # if success:
    #     print("\n=== WYNIK: SUKCES - Klucz został poprawnie odzyskany! ===")
    # else:
    #     print("\n=== WYNIK: PORAŻKA - Nie udało się odzyskać klucza. ===")

        
    # PRZYKŁAD UŻYCIA
    # Tworzenie solvera dla 3 rund DES
    rounds = 1
    key = 0x01923572
    des = DES(key, rounds) #0x12345678
    solver = DES_MILP_Solver(num_rounds=rounds, input_diff_L=0x0, input_diff_R=0x00040000, des=des, cutoff=0)

    # Rozwiązanie problemu
    status = solver.solve(time_limit=30)

    # Wypisanie wyników
    if status == 1:  # Optimal
        solver.print_solution()
    else:
        print(f"Nie udało się znaleźć optymalnego rozwiązania.")

    attack = DifferentialAttackDES(des, solver.get_solution())

    attack.full_attack(key)


def plot_diff_histogram(differences, deltaP_hex, top_n=20):
    # Licz częstości różnic
    diff_counts = Counter(differences)

    # Weź top N najczęstszych
    common_diffs = diff_counts.most_common(top_n)

    # Przygotuj dane do wykresu
    diff_hex = [d for d, _ in common_diffs]
    counts = [count for _, count in common_diffs]

    # Twórz histogram
    plt.figure(figsize=(12, 6))
    bars = plt.bar(diff_hex, counts, color='skyblue')
    plt.xlabel('ΔC (różnica szyfrogramów)')
    plt.ylabel('Liczba wystąpień')
    plt.title(f'Histogram ΔC dla ΔP = {deltaP_hex} (top {top_n})')
    plt.xticks(rotation=45, ha='right')

    # Dodaj wartości na słupkach
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 str(count), ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.show()

    # Zwróć najczęstszą różnicę
    most_common = common_diffs[0]
    print(f"Najczęstsza ΔC: 0x{most_common[0]:016X} występuje {most_common[1]} razy")
    print(f"Prawdopodobieństwo: {most_common[1] / len(differences):.6f}")

    return most_common[0]

if __name__ == "__main__":
    main()