"""
Benchmark: costo en CPU del servidor cuando N clientes fallan
simultáneamente y disparan el tarpit (3er fallo -> modo "cpu").

Esto responde a la pregunta del THREAT_MODEL.md, sección 2:
"¿el propio tarpit puede convertirse en un vector de auto-DoS?"

Uso:
    python3 benchmarks/bench_tarpit_concurrency.py --workers 4 --seconds 0.5

Nota: esto mide el costo en ESTA máquina (sandbox). Los números absolutos
no son representativos de tu infraestructura real de producción — sirven
para comparar backend Python vs nativo y para dimensionar límites
(p. ej. cuántos tarpits concurrentes son tolerables antes de saturar CPU),
no como benchmark final de capacidad.
"""

from __future__ import annotations

import argparse
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from smart_token_prod.core import SequentialTarpit
from smart_token_prod.native import NativeTarpit, is_available


def run_one_tarpit_to_trigger(backend: str, tarpit_seconds: float, worker_id: int) -> float:
    key = hashlib.sha256(f"worker-{worker_id}".encode()).digest()
    cls = NativeTarpit if backend == "native" else SequentialTarpit
    tarpit = cls(key, "cpu", tarpit_seconds)

    start = time.perf_counter()
    tarpit.register_failure()  # 1: warning
    tarpit.register_failure()  # 2: key mutation
    tarpit.register_failure()  # 3: CPU tarpit (bloqueante)
    return time.perf_counter() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=4, help="Clientes fallando en paralelo")
    parser.add_argument("--seconds", type=float, default=0.5, help="Duración del tarpit por intento")
    parser.add_argument("--backend", choices=["python", "native", "both"], default="both")
    args = parser.parse_args()

    backends = ["python", "native"] if args.backend == "both" else [args.backend]

    for backend in backends:
        if backend == "native" and not is_available():
            print(f"[{backend}] omitido: libfriction.so no disponible")
            continue

        print(f"\n=== backend={backend}  workers={args.workers}  tarpit_seconds={args.seconds} ===")
        wall_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [
                pool.submit(run_one_tarpit_to_trigger, backend, args.seconds, i)
                for i in range(args.workers)
            ]
            durations = [f.result() for f in as_completed(futures)]
        wall_elapsed = time.perf_counter() - wall_start

        print(f"tiempo total de pared: {wall_elapsed:.3f}s")
        print(f"duración por worker  : min={min(durations):.3f}s max={max(durations):.3f}s "
              f"avg={sum(durations)/len(durations):.3f}s")
        print(
            "interpretación: si wall_elapsed crece mucho más que "
            f"~{args.seconds:.2f}s al aumentar --workers, la CPU del servidor "
            "se está saturando con el tarpit (riesgo de auto-DoS, ver THREAT_MODEL.md)."
        )


if __name__ == "__main__":
    main()
