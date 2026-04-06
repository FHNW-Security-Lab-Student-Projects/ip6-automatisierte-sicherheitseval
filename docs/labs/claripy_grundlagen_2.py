import claripy

x = claripy.BVS("x", 32)

s = claripy.Solver()

s.add(x > 10)
s.add(x < 20)

if s.satisfiable():
    print("Lösung gefunden!")
    loesung_x = s.eval(x, 24)
    for i, val in enumerate(loesung_x):
        print(f"Lösung {i+1}: {val}")
else:
    print("Keine Lösung möglich (UNSAT).")
