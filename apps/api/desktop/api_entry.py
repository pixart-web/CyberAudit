from cyberaudit.desktop_runtime import api_main, guarded_entrypoint

if __name__ == "__main__":
    raise SystemExit(guarded_entrypoint(api_main))
