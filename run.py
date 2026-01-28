import sys
import os

# Dodajemy folder 'src' do ścieżki Pythona, 
# dzięki temu importy typu "from des import DES" zadziałają bez błędów.
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from cryptominidesmilp import main

if __name__ == "__main__":
    with open("output.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        try:
            main()
        except ImportError as e:
            print(f"Błąd importu! Upewnij się, że masz zainstalowane biblioteki.")
            print(f"Szczegóły: {e}")
            print("Spróbuj uruchomić przez: poetry run python run.py")