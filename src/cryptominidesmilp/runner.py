import sys
# Importujemy funkcjonalności z sąsiednich pakietów
from des import DES
from differentialAttack import find_best_characteristic, run_attack
from src.differentialAttack.milp_setup import DES_MILP_Solver

def main():
    print("=== CryptoMiniDesMILP: DES Differential Attack Demo ===\n")
    
    # 1. Uruchomienie MILP (dla celów informacyjnych szukamy charakterystyki dla 5 rund)
    print("KROK 1: Szukanie charakterystyki metodą MILP (dla 5 rund)...")
    active_sboxes = find_best_characteristic(rounds=5)
    for r, sboxes in active_sboxes.items():
        print(f"  Runda {r+1}: Aktywne S-boxy {sboxes}")
    
    print("\n" + "-"*50 + "\n")
    
    # 2. Uruchomienie Ataku
    print("KROK 2: Próba odzyskania klucza dla 6 RUND...")
    
    # Ustalamy sekretny klucz
    secret_key = 0x133457799BBDDFF1
    
    # Uruchamiamy atak na 6 rund
    # Zwiększamy liczbę par, ponieważ atak na 6 rund wymaga więcej danych niż na 4
    success = run_attack(target_rounds=6, real_key=secret_key, pairs_count=10000)
    
    if success:
        print("\n=== WYNIK: SUKCES - Klucz został poprawnie odzyskany! ===")
    else:
        print("\n=== WYNIK: PORAŻKA - Nie udało się odzyskać klucza. ===")

        
    # PRZYKŁAD UŻYCIA
    # Tworzenie solvera dla 3 rund DES
    solver = DES_MILP_Solver(num_rounds=3)

    # Rozwiązanie problemu
    status = solver.solve(time_limit=30)

    # Wypisanie wyników
    if status == 1:  # Optimal
        solver.print_solution()
    else:
        print(f"Nie udało się znaleźć optymalnego rozwiązania.")

if __name__ == "__main__":
    main()