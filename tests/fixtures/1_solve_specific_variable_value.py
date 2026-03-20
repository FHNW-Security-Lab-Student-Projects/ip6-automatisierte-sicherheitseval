import angr

proj = angr.Project("./tests/1_specific_variable_value", auto_load_libs=False)

state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Suche nach dem Zustand, der "Correct!" ausgibt
simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1))

if simgr.found:
    found = simgr.found[0]
    print("Gefundene Eingabe:", found.posix.dumps(0))
else:
    print("Kein Pfad gefunden.")