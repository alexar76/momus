# Operar el ciclo de autorreparación: claves, ajustes y qué se redespliega

> 🌐 [English](self-healing-operations.md) · [Русский](self-healing-operations.ru.md) · **Español** · [Français](self-healing-operations.fr.md) · [中文](self-healing-operations.zh.md)

> **Cambiarlo para que fusione solo** — una casilla, con diagramas: [switch-to-auto-merge.es.md](switch-to-auto-merge.es.md).

> **Demostrado de extremo a extremo** — el objetivo de práctica, los tres ejercicios y por qué una corrección llega a producción antes que a `main`: [proving-the-loop.es.md](proving-the-loop.es.md).

> **Qué detiene un parche malo** — cada salvaguarda por la que pasa una reparación desatendida, y el incidente detrás de cada una: [autonomous-repair-guards.es.md](autonomous-repair-guards.es.md).

MOMUS encuentra un fallo, la AI-Factory escribe un parche, la flota lo compila, MOMUS la somete a su puerta de despliegue, un agente de nodo lo publica y una regresión lo revierte. Esta página es el lado del operador: qué servicio vive dónde, qué variable de entorno activa qué rechazo y —la pregunta que originó esta página— **cuántas cosas hay que redesplegar al cambiar el código.**

## La respuesta corta sobre redespliegues

**Una.** No dos fábricas.

La ruta de redacción de parches (`POST /api/remediation/fix`) se monta **solo** donde `AIFACTORY_REMEDIATION_FIX_ENABLED=1`. En la instancia pública esa variable no está definida, así que la ruta no existe allí en absoluto — no es «existe pero rechaza». La distinción es deliberada: `web/frontend/next.config.js` reescribe `/api/:path*` hacia la API interna, de modo que una ruta simplemente desactivada seguiría siendo un extremo públicamente alcanzable que responde 403: superficie de ataque nueva a cambio de nada.

Por tanto:

| Lo que cambiaste | Lo que redespliegas |
|---|---|
| `web/backend/api/remediation.py`, `web/backend/services/remediation_fix.py` | solo la **instancia de remediación** |
| `skopos/skopos/remediation/*` | el **director** (`skopos-remediation`) |
| `momus/momus/*` | **momus-backend** |
| el código de compilación/despliegue del agente de nodo | el **agente** en cada host de la flota |
| `core/`, `llm/` compartidos | las instancias que realmente te importen — algo que ya era cierto para cada satélite de este monorepo y que la remediación no cambia |

La fábrica pública no ejecuta remediación, así que los cambios de remediación no pueden afectarla.

## Los dos modos

Cada componente que el bucle vigila está en uno de dos modos, y la diferencia es un solo paso al
final. El comienzo es idéntico: MOMUS sondea, confirma un hallazgo, firma un tique de reparación,
el conductor hace que la fábrica redacte un parche, y el parche aterriza en una rama `momus/fix-…`
como un diff revisable.

**Autorreparación.** Una mano de despliegue de ese componente construye la rama, MOMUS repite la
sonda contra el candidato, y sólo un veredicto `fixed` firmado promueve la imagen y recrea el
servicio. No se despierta a nadie. Es el modo de un componente que tiene una mano instalada y una
imagen que esa mano sabe construir.

**Sólo parche.** Ocurre todo lo anterior salvo el último paso: la rama queda lista y el trabajo
espera. Una persona revisa el diff y lo despliega. No es un modo degradado — es el correcto allí
donde una mano no tendría nada que promover, y el que conviene elegir donde uno querría leer el
parche antes de que se ejecute.

En qué modo está un componente es una propiedad de su despliegue, no un ajuste que recordar:

| componente | modo | por qué |
|---|---|---|
| canario | autorreparación | el campo de pruebas del bucle; existe para romperse y arreglarse |
| gaia | autorreparación | proyecto compose propio, construido desde este repositorio |
| hub (producción) | autorreparación | su mano alcanza el relé de flota; véase *Quién corre dónde* |
| oracles | sólo parche | se construye desde otro checkout, ninguna mano puede producir su imagen |
| MOMUS, Treasury, SKOPOS, la puerta | ninguno | rechazados en código — véase *Contención* |

**Pasar un componente a sólo parche** es una propiedad de su mano; hay tres palancas, de menor a
mayor severidad:

* `SKOPOS_AGENT_DRY_RUN=1` — la mano verifica la orden e imprime el comando que ejecutaría. Todo
  lo anterior sigue ocurriendo, así que es el modo para ejercitar el bucle sin mover nada.
* `SKOPOS_AGENT_SERVICE_ALLOWLIST=` (vacío) — la mano rechaza toda orden. Aparca un host sin
  tocar el resto de la flota.
* `systemctl stop skopos-deploy-hand@<componente>` — las órdenes se acumulan en el conductor y
  caducan.

**Pasar el bucle entero** es `SKOPOS_REMEDIATION_DRY_RUN=1` en el conductor: hallazgos, tiques y
parches continúan, y nunca se ordena nada.

No hay palanca que convierta sólo-parche en autorreparación para un componente sin mano. Es
deliberado: un componente se vuelve autorreparable por tener dónde desplegarse, no por estar
marcado como tal.

## Quién corre dónde

| Rol | Servicio | Escucha en |
|---|---|---|
| encuentra fallos y es la **puerta de despliegue** | `momus-backend` | loopback |
| paga recompensas (clave aparte que MOMUS nunca tiene) | `momus-treasury` | loopback |
| dirige una tarea de remediación | `skopos-remediation` | loopback |
| redacta parches | la instancia de remediación de la fábrica | loopback |
| remoto git (transporte **y** rastro de auditoría) | Gitea `alexar76/aicom` | loopback (`:3000` HTTP, `:2222` SSH) |
| compila y publica | el agente de nodo en el host destino | solo salida, ningún puerto |
| lo primero que se rompe y se repara | `momus-canary` | loopback |

Nada aquí abre un puerto entrante en un host de la flota. El agente consulta; nunca se le llama.

## La cadena, y por qué existe cada paso

```
MOMUS encuentra ──ticket firmado (A2A)──▶ director
  ├─ 1. la fábrica redacta un DIFF unificado   (nunca una imagen; no compila)
  ├─ 2. el director confirma y empuja momus/fix-<finding_id>
  │        la rama es EL transporte hacia el compilador Y el artefacto que revisa una persona
  ├─ 3. la BuildOrder firmada nombra un COMMIT  (nunca código en línea)
  │        el agente: lo trae, rechaza cualquier rama fuera de SU lista de prefijos, rechaza un
  │        commit que no sea la punta de esa rama, compila con SU propia receta, informa el DIGEST
  │        y arranca <servicio>-candidate para que la puerta tenga algo que sondear
  ├─ 4. MOMUS sondea el CANDIDATO             (previo a la promoción, atado a ese digest)
  ├─ 5. la DeployOrder firmada lleva el digest
  │        el agente: anota el digest en curso, mueve la etiqueta de compose a la nueva, recrea,
  │        aplica la puerta de salud y verifica que el contenedor SEA de verdad ese digest
  ├─ 6. MOMUS reexamina el servicio EN VIVO
  └─ 7. si aún se reproduce → RollbackOrder firmada → el agente restaura el digest que anotó
```

Dos omisiones convertían esto en teatro, y conviene conocerlas porque los síntomas engañaban:

* **Nadie compilaba una imagen.** Así que «desplegar» recreaba el contenedor desde la imagen que ya estaba en el host, la puerta examinaba precisamente la compilación que pretendía sustituir, respondía con razón «sigue reproduciéndose», y la escalada culpaba al parche.
* **`DeployOrder.image` no lo leía nadie.** El campo existía y llevaba un valor.

## Contención: la orden dice *cuál*, el host dice *qué está permitido*

Cada restricción de abajo la impone el **agente**, desde su configuración local. Quien llama no puede ampliar ninguna.

* el agente compila y despliega solo servicios de su propio `SKOPOS_AGENT_SERVICE_ALLOWLIST`;
* compila solo desde ramas que encajen en su propio `SKOPOS_AGENT_BRANCH_PREFIXES`;
* compila solo con el Dockerfile y el contexto de su propio `SKOPOS_AGENT_BUILD_MAP`;
* despliega solo imágenes **que él mismo compiló, para ese mismo servicio** (comprobado contra su propio diario de compilaciones), así que una orden que nombre cualquier otra imagen del host no resuelve a nada;
* rechaza promover una imagen nueva con un veredicto que examinó el servicio *en vivo*. `gated` va dentro del FixVerdict firmado, así que no puede reetiquetarse en el cable;
* una `RollbackOrder` **no lleva imagen alguna**: nombra una orden anterior, y el destino sale de lo que el agente anotó como en ejecución antes de ese despliegue. Por eso la vía de reversión no puede publicar nada nuevo, y por eso se le permite prescindir del veredicto de MOMUS que un despliegue directo sí exige (se revierte precisamente cuando ese veredicto resultó equivocado).

`main` está protegida en el servidor **y** el director se niega a empujar fuera de su prefijo de rama. Dos políticas independientes, porque que una esté mal configurada no debe bastar.

> **Compruébalo antes de confiar en ello.** La protección de `main` en `alexar76/aicom` tiene ahora `enable_push=true` con la lista `['alexar76']`. Cualquier cosa que empuje *como ese usuario* puede llegar a `main` directamente. Empuja con una **clave de despliegue** por repositorio, no con un token de acceso de usuario (los tokens de Gitea son de usuario: `write:repository` cubre todos los repositorios del propietario). `push_whitelist_deploy_keys` es `false`, así que una clave de despliegue no alcanza `main`.
>
> Sobre demostrarlo: **no** lo pruebes empujando de verdad a `main` en un host con un ejecutor de Gitea Actions instalado — un empuje a `main` puede disparar un flujo de despliegue. Lee la configuración de protección en su lugar.

## Ajustes

### La instancia de remediación de la fábrica

| Variable | Por defecto | Qué hace |
|---|---|---|
| `AIFACTORY_REMEDIATION_FIX_ENABLED` | sin definir | **El interruptor maestro.** Sin definir ⇒ la ruta no se monta en absoluto. |
| `AIFACTORY_REMEDIATION_KEY` | sin definir | Secreto compartido con el director. Obligatorio en producción; sin definir en producción ⇒ 503, nunca abierto. |
| `AIFACTORY_REMEDIATION_MOMUS_PUBKEY` | sin definir | La clave Ed25519 de MOMUS. Sin ella un ticket no puede verificarse y toda petición se rechaza. |
| `AIFACTORY_REMEDIATION_SCOPE` | canario + hub | JSON `{componente: [rutas]}`. Los **únicos** ficheros que un parche para ese componente puede tocar. Un modelo que responda con una ruta fuera de la lista es rechazado. Hub queda en `aimarket-hub/aimarket_hub/unpaid_invoke.py`. MOMUS / Treasury / la puerta no están. |
| `AIFACTORY_REMEDIATION_LLM_BUDGET_S` | `240` | La ruta pide el contenido completo de los ficheros, así que esto tarda minutos, no segundos. Debe quedar POR DEBAJO del tiempo de espera del cliente del director. |
| `AIFACTORY_DEMO_READONLY` | — | Si es `1`, la redacción de parches se rechaza: es el guardián de la demo pública, y una demo pública no es el lugar de un parcheador autónomo. |

### El director

| Variable | Por defecto | Qué hace |
|---|---|---|
| `SKOPOS_REMEDIATION_ENABLED` | `1` | Interruptor maestro. `0` ⇒ nunca se firma una orden de despliegue. |
| `SKOPOS_REMEDIATION_DRY_RUN` | `0` | `1` ⇒ la cadena corre y no firma nada que se publique. Y lo dice con franqueza: la tarea cierra declarando que no se desplegó nada. En vivo (`0`) es el valor por defecto para canary + hub. |
| `SKOPOS_FACTORY_URL` | sin definir | Sin definir **estando en vivo** es un fallo de configuración, no un valor de reserva: antes provocaba la síntesis de un parche falso. |
| `SKOPOS_MOMUS_PUBKEY` | sin definir | Obligatoria fuera de dry-run: un ticket no verificable se rechaza. |
| `SKOPOS_GIT_REPO_URL` / `SKOPOS_GIT_SSH_KEY` | sin definir | El remoto de la rama de corrección y su credencial (una clave de despliegue). |
| `SKOPOS_FIX_BRANCH_PREFIX` | `momus/fix-` | También el prefijo fuera del cual el director se niega a empujar. |
| `SKOPOS_AGENT_TOKEN` | sin definir | El token de inscripción que presenta la mano de despliegue. Sin él el director no entrega órdenes fuera de dry-run (fail-closed) y la mano recibe 503 indefinidamente. |
| `SKOPOS_DEPLOY_RESULT_TIMEOUT_S` | `420` | Cuánto esperar el informe del agente. Debe superar su intervalo de consulta + el tiempo de compose + la espera de salud. |
| `SKOPOS_MAX_DEPLOYS_PER_DAY` | `6` | Estrangulador. Alcanzado ⇒ rechazo, el cortacircuitos **no** salta. |
| `SKOPOS_MAX_DEPLOYS_PER_COMPONENT_PER_DAY` | `2` | Redesplegar un servicio repetidamente es agitación, no remediación. |
| `SKOPOS_MAX_ROLLBACKS` | `2` | **La señal que importa.** Dos reversiones en la ventana ⇒ salta el cortacircuitos. |
| `SKOPOS_MAX_ROLLBACK_RATE` | `0.34` | Junto con `SKOPOS_BREAKER_MIN_SAMPLE` (`5`), porque 1 de 1 no es una tasa de fallo del 100%. |
| `SKOPOS_MAX_CONSECUTIVE_FAILURES` | `3` | Entregar a una persona un componente que no se puede arreglar. |
| `SKOPOS_OPERATOR_TOKEN` | sin definir | Necesario para rearmar un cortacircuitos disparado. Sin definir ⇒ nadie puede, que es la dirección segura. |

### El agente de nodo

| Variable | Por defecto | Qué hace |
|---|---|---|
| `SKOPOS_AGENT_DRY_RUN` | `0` | `1` ⇒ valida e imprime la orden, sin ejecutar nada. En vivo (`0`) es el valor por defecto. |
| `SKOPOS_AGENT_SERVICE_ALLOWLIST` | `canary,hub` | Separado por comas. Sin definir ⇒ canary + hub (y sus alias de compose). Vacío ⇒ el agente no puede tocar nada. MOMUS / Treasury no entran. |
| `SKOPOS_AGENT_BRANCH_PREFIXES` | `momus/fix-` | Local. Compilar desde `main` sería compilar lo último que alguien fusionó. |
| `SKOPOS_AGENT_BUILD_MAP` | `{}` | JSON `{servicio: {dockerfile, context, image_ref, network, compose_service}}`. Sin receta ⇒ se niega a compilar ese servicio. **`compose_service` es obligatorio donde el nombre del componente y el del servicio de compose difieren** — MOMUS llama a su objetivo `canary` mientras el servicio de compose es `momus-canary`, y sin ese mapeo cada despliegue apunta a un servicio que no existe. |
| `SKOPOS_AGENT_REPO_URL` | sin definir | De dónde puede venir el código. Nunca se lee de una orden. |
| `SKOPOS_AGENT_HEALTH_WAIT_S` | `20` | Cuánto tiempo tiene un contenedor para demostrar que no está en bucle de caídas. Que `compose up` salga con 0 no es un veredicto. |

## Observarlo y detenerlo

* `GET /remediation/health` — las cifras, más el estado y los umbrales del cortacircuitos.
* `GET /metrics` — Prometheus. La alerta que importa es **`skopos_remediation_rollback_rate`**: reversiones por parche publicado, es decir, con qué frecuencia el veredicto de la puerta y la realidad discrepan. Un parche que la puerta rechaza no cuesta nada; uno que se publicó y hubo que revertir es la forma peligrosa.
* `GET /api/remediation/stats` — el resumen que lee LOGOS. No renombres sus claves.
* `POST /remediation/breaker/clear` con `x-skopos-operator` — la **única** forma de rearmar un cortacircuitos disparado. Nada en el código lo rearma: un cortacircuitos que se reiniciase solo quedaría derrotado por el mismo bucle de caídas que existe para interrumpir, y «se recuperó solo» es indistinguible de «nadie se enteró». Un disparo sobrevive a un reinicio, y un fichero de estado ilegible falla cerrado.

## Activarlo, en el orden defendible

1. Define `AIFACTORY_REMEDIATION_*` en la instancia **privada** y confirma que `GET /api/remediation/fix/status` muestra `enabled: true` y el alcance que esperas.
2. Da al director su credencial git y **demuestra que `main` rechaza un empuje** antes de confiar en ella.
3. Arranca el agente de nodo. Los valores por defecto están en vivo: `SKOPOS_AGENT_DRY_RUN=0` y `SKOPOS_AGENT_SERVICE_ALLOWLIST=canary,hub`. MOMUS / Treasury no entran.
4. Confirma que `/remediation/health` muestra dry-run desactivado y que el agente reclama órdenes.
5. Rompe el canario a propósito, observa cómo el ciclo lo repara y redespliega, y lee la rama que empujó.
6. Hub ya está en el mismo camino. Un veredicto `fixed` sigue sin fusionarse a `main`.
7. Para aparcar: `SKOPOS_AGENT_DRY_RUN=1` y `SKOPOS_REMEDIATION_DRY_RUN=1`, o vacía la lista.

Los hallazgos contra el núcleo de seguridad (MOMUS, la Treasury, la propia puerta) no toman esta vía en absoluto: `escalation_for` los encamina a gobernanza humana más un verificador operado de forma independiente, porque un auditor que se arregla a sí mismo ha certificado su propio trabajo.
