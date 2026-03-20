import angr
import claripy
import logging

# Logging reduzieren, damit wir nur das Wichtige sehen
logging.getLogger('angr').setLevel(logging.ERROR)

# 1. Projekt laden
proj = angr.Project("tests/4_logic", auto_load_libs=False)

# 2. Startzustand erstellen
# Wir starten am Entry Point. 
# WICHTIG: Wir sagen angr, dass der Input symbolisch sein soll.
# Da fgets liest, wird angr den Input-Buffer automatisch symbolisch behandeln,
# sobald das Programm versucht, Daten zu lesen.
init_state = proj.factory.entry_state()

# Optional: Wir können den Input explizit als symbolische Variable definieren,
# um mehr Kontrolle zu haben (wie im Cheat Sheet Section 4.2).
# Das ist oft robuster als sich auf die automatische Erkennung zu verlassen.
# Wir erstellen 8 symbolische Bytes (64 Bits) für das Passwort.
password = claripy.BVS('password', 8 * 8) 

# Wir müssen diesen symbolischen Wert in den stdin des States injizieren.
# Wir ersetzen den Standard-Input durch unsere symbolische Variable.
init_state.posix.stdin.write(password)

# 3. Simulation Manager erstellen
simgr = proj.factory.simulation_manager(init_state)

# 4. Kriterien definieren
def is_successful(state):
    # Wir prüfen die stdout Ausgabe
    return b"Access granted!" in state.posix.dumps(1)

def should_abort(state):
    return b"Access denied!" in state.posix.dumps(1)

# 5. Exploration starten
print("Starte symbolische Ausführung...")
simgr.explore(find=is_successful, avoid=should_abort)

# 6. Ergebnis extrahieren
if simgr.found:
    solution_state = simgr.found[0]
    
    # HIER IST DER SCHLÜSSEL:
    # Wir haben im State eine symbolische Variable 'password' erstellt.
    # Der Solver hat nun alle Constraints gesammelt (die mathematische Gleichung).
    # Wir fragen den Solver: "Welcher konkrete Wert für 'password' erfüllt alle Constraints?"
    
    concrete_password = solution_state.solver.eval(password, cast_to=bytes)
    
    print(f"[*] Lösung gefunden!")
    print(f"[*] Passwort (Bytes): {concrete_password}")
    print(f"[*] Passwort (String): {concrete_password.decode()}")
    
    # Verifikation
    import subprocess
    result = subprocess.run(["./math_crackme"], input=concrete_password, capture_output=True)
    print(f"[*] Programm Antwort: {result.stdout.decode()}")
    
else:
    print("[-] Keine Lösung gefunden.")