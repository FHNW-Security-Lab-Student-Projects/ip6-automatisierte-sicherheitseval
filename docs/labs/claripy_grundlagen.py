import claripy

x = claripy.BVS("x", 32)

s = claripy.Solver()

s.add(x == 42)

if s.satisfiable():
    print("Lösung gefunden!")
    print(s.eval(x, 1)[0])  # Gibt den konkreten Wert von x zurück
else:
    print("Keine Lösung möglich (UNSAT).")
