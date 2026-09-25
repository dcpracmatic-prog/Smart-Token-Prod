# Modelo de amenazas — Smart Token Prod (v0.10.5)

Estado: **borrador técnico interno**. Esto NO sustituye una auditoría de
seguridad independiente — es el punto de partida que un auditor necesitaría
para empezar a trabajar, y el mínimo que cualquier cliente serio va a pedir
antes de confiar en el sistema.


## 0. Contrato de integridad de fricción (v0.10.5)

**Defensa base autónoma (file-borne):**  
El `friction_snapshot` y el `friction_mac` viajan **dentro del propio archivo `.stok`**.  
La trampa lógica (fases 1→2→3, ladder, hang) funciona sin red y sin configuración del operador.  
El FrictionStore compartido (FileFrictionStore / Redis) es un refuerzo **opcional** exclusivo del escenario multi-host en el que varias réplicas desean compartir el mismo contador de fallos. En el caso normal (un archivo defendiéndose solo) no aplica ninguna “flojera del operador”: no hay nada que configurar para que la trampa esté activa.



- La trampa lógica (fases / ladder / hang) en el path oficial
  (`open_stok` / SDK) solo opera sobre un `friction_snapshot` con
  **`friction_mac` válido** (HMAC keyed por el shared secret ML-KEM).
- MAC inválido o ausente (binding v2) → **fail-closed**: DENIED, OPEN
  prohibido, **no** se sustituye el snapshot por `{}`, bytes previos en
  disco intactos. Esto cierra el bypass de auditoría A1 (bit-flip MAC →
  open gratis).
- Open sin `sk`/`ss`: DENY de solo lectura (sin mutar friction; no hay
  re-MAC íntegro).
- MAC verificado solo contra snapshot **en disco**; el store compartido
  se mergea después (evita DoS fail-closed por store≻disk).
- Tras bitrot/tamper de MAC: dueño re-firma con `repair_friction_mac`
  (deuda intacta); no hay OPEN gratis.
- Lock de open: flock del inode `.stok` + writes vía fd + verificación
  `(dev,ino)` (unlink+recreate del path bajo lock → fail-closed; no
  sidecar).
- Denegaciones API opacas por defecto (`reveal_friction=False`) en
  `open_stok` **y** `SmartTokenProd.open`; inspección =
  `friction_status` / CLI `status` / opt-in.
- Hang de fase 3: clave = **`fail_count >= 3`**. Tope process-local
  `SMART_TOKEN_MAX_CONCURRENT_HANGS` (default 2); **no** hay backpressure
  distribuido Redis/cluster.
- **B1 residual:** con `sk`+master+fuente, un atacante puede
  reimplementar decaps+KDF+AES offline y omitir la máquina de estados;
  la dureza cae a Argon2. El producto **no** afirma lo contrario. La
  garantía file-borne es contra manipulación del `.stok` **sin** `sk`
  en la ruta autenticada.

Detalle de remediación: `docs/AUDIT_REMEDIATION.md`.

## 1. Qué protege el sistema

- **Confidencialidad del payload** en tránsito/reposo, mediante ML-KEM-768
  (post-cuántico) para el intercambio de clave + AES-256-GCM para el cifrado
  autenticado del contenido.
- **Resistencia a fuerza bruta online** contra el flujo de apertura, mediante
  la máquina de estados de fricción (aviso → mutación de clave → tarpit de
  CPU / bloqueo).
- **Detección de manipulación** vía el tag de autenticación de AES-GCM
  (cualquier alteración del ciphertext o del AAD invalida el descifrado).

## 2. Qué NO protege (explícito, para no venderlo de más)

- **Ataques de canal lateral (side-channel)**: timing, cache, consumo
  eléctrico. Ni el núcleo Python ni el C++ actual están escritos en tiempo
  constante. La comparación `ss == self.shared_secret` en Python, por
  ejemplo, no es constant-time.
- **Compromiso del proceso/host**: si un atacante tiene ejecución de código
  en la máquina donde vive `sk`, el token no ofrece ninguna protección — la
  clave secreta está en memoria de proceso sin cifrar (ver `keymgmt.py`,
  sección de gestión de claves).
- **Ataques distribuidos multi-host sin store común**: en un solo host (o
  NFS/disco compartido) `FileFrictionStore` + lock de `.stok` hacen que N
  workers sumen al **mismo** `fail_count`. Comprobado con
  `scripts/validate_replicas.py`. Réplicas en máquinas distintas siguen
  necesitando Redis (`RedisFrictionStore`) u otro store de red; si cada
  host tiene su propio disco, el atacante otra vez parte los intentos.
- **Denegación de servicio (DoS) propia**: el tarpit/hang consume ciclos
  del *servidor*. v0.10.2 añade tope **process-local** de hangs
  concurrentes (`SMART_TOKEN_MAX_CONCURRENT_HANGS`, default 2): slots
  llenos → DENIED sin entrar en otro grind infinito (fricción ya
  persistida). **Residual:** multi-proceso / multi-host sin store
  compartido y sin límite externo siguen pudiendo saturar CPU; no hay
  semáforo Redis/cluster. **Medido** (`benchmarks/bench_tarpit_concurrency.py`):
  Python ~2.2x wall bajo contención GIL; native ~1.2x — preferir
  `friction_backend="native"` en producción.
- **Replay de mensajes legítimos**: no hay nonce/timestamp de aplicación a
  nivel de protocolo que impida reproducir una apertura legítima capturada
  (el nonce de AES-GCM protege el cifrado, no evita el replay del mensaje
  completo si el ciphertext se reenvía tal cual).
- **Post-cuántico "en tránsito" solamente**: ML-KEM protege el intercambio
  de clave; no hay firma post-cuántica (ML-DSA/SLH-DSA) para autenticar el
  origen del mensaje — si eso es parte del caso de uso, falta.
- **Bypass offline de la máquina de estados con `sk`+fuente (B1)**:
  quien reimplementa las primitivas puede omitir tarpit/ladder/hang
  oficiales; no obtiene plaintext sin master (binding v2). Mitigado
  en producto vía claims atados a `open_stok` + MAC fail-closed.
- **Ingeniería social / phishing sobre el `master_secret`**: la coherencia
  depende de un secreto compartido; su distribución y custodia están fuera
  del alcance del código actual.

## 3. Superficie de ataque

| Componente | Expuesto a | Riesgo actual |
|---|---|---|
| `sk` (ML-KEM secret key) | Memoria de proceso | Alto sin HSM/KMS |
| `master_secret` | Quien instancia `SmartTokenProd` | Sin gestión — responsabilidad del integrador |
| Estado de fricción | RAM (o store si se usa `persistence.py`) | Medio — mitigable con store compartido |
| `libfriction.so` | Carga dinámica por ruta relativa | Bajo, pero falta verificación de integridad (firma/hash) antes de `dlopen` |
| Canal de red (fuera de este repo) | No definido aquí | El transporte (TLS, autenticación mutua) es responsabilidad del sistema que integre esta librería |

## 4. Supuestos que hay que validar con un auditor externo

1. Que la implementación de `pqcrypto` para ML-KEM-768 es constant-time y
   está libre de vulnerabilidades conocidas (no se puede confirmar solo
   leyendo el código de este repo).
2. Que la métrica de "coherencia" (`coherence_metric`) no introduce un canal
   de filtración de información sobre `master_secret` a través de su valor
   o del tiempo que toma calcularla.
3. Que el tarpit de CPU no es evitable simplemente matando/reiniciando el
   proceso cliente (si el estado no está en un `FrictionStore` persistente,
   sí lo es — ver sección 2).

## 5. Siguiente paso recomendado

Antes de cualquier conversación comercial con un cliente que maneje datos
sensibles: contratar una auditoría de seguridad de terceros que cubra al
menos las secciones 2 y 4 de este documento. Esa auditoría **no se puede
hacer dentro de este entorno** — requiere un auditor humano con
credenciales/reputación verificable.
