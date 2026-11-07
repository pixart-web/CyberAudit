from cyberaudit.desktop_runtime import guarded_entrypoint, worker_main

if __name__ == "__main__":
    raise SystemExit(guarded_entrypoint(worker_main))
