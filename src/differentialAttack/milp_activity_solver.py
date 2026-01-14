import pulp

def find_best_characteristic(rounds=3):
    """
    Znajduje minimalną liczbę aktywnych S-boxów przy użyciu MILP.
    Zwraca strukturę aktywnych S-boxów.
    """
    prob = pulp.LpProblem("DES_Differential_Path", pulp.LpMinimize)
    active_sboxes = {}

    # Definicja zmiennych
    for r in range(rounds):
        for s in range(8):
            active_sboxes[(r, s)] = pulp.LpVariable(f"S_{r}_{s}", cat=pulp.LpBinary)

    # Funkcja celu
    prob += pulp.lpSum(active_sboxes.values())

    # Ograniczenie: Przynajmniej jeden aktywny S-box na początku
    prob += pulp.lpSum([active_sboxes[(0, s)] for s in range(8)]) >= 1

    # Rozwiązanie (wyciszone komunikaty solvera)
    prob.solve(pulp.PULP_CBC_CMD(msg=False))
    
    # Zbieranie wyników
    result_map = {}
    for r in range(rounds):
        result_map[r] = [s for s in range(8) if pulp.value(active_sboxes[(r, s)]) == 1.0]
        
    return result_map