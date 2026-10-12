# Demostrar el bucle — el objetivo de práctica, y por qué las correcciones llegan a producción antes que a `main`

> 🌐 [English](proving-the-loop.md) · [Русский](proving-the-loop.ru.md) · **Español** · [Français](proving-the-loop.fr.md) · [中文](proving-the-loop.zh.md)

> **Cambiarlo para que fusione solo** — una casilla, con diagramas: [switch-to-auto-merge.es.md](switch-to-auto-merge.es.md).

> **Las barreras que atraviesa un parche** — [autonomous-repair-guards.es.md](autonomous-repair-guards.es.md) ·
> **Ajustes del operador** — [self-healing-operations.es.md](self-healing-operations.es.md)

El 30 de agosto de 2026 el bucle de autorreparación arregló un defecto real tres veces, sin
supervisión, y cada vez se verificó desde fuera del propio bucle. Esta página cuenta qué hizo
falta, qué quedó demostrado, y las dos cosas que un operador tiene que saber: **una corrección
llega a producción antes que a `main`**, y **el canario nunca puede ser aquello sobre lo que se
demuestra el bucle**.

## El bucle nunca se había probado, y nadie lo había notado

Todos los componentes reales pasan sus propias comprobaciones de contrato —`gaia`, `oracles` y el
hub escanean limpios, que es el objetivo de haberlos construido con cuidado. Así que los únicos
hallazgos del corpus eran los del canario, y el canario es un accesorio que anuncia un contrato y
lo rompe a sabiendas.

Cinco intentos autónomos de reparación se habían leído como fallo del modelo. No lo eran. El
archivo que se les pedía parchear, `momus/canary/canary.py`, empieza así:

> un servicio deliberadamente no conforme … un servicio que anuncia un contrato y luego lo rompe
> a sabiendas … **Dos cosas deben seguir siendo verdad, y ambas son portantes para la honestidad.**

Un modelo cuidadoso lee eso y se niega —y lo explica. Cada una de esas negativas era correcta. Y
los intentos que **sí** produjeron código fueron las peores respuestas: pisaban un invariante
documentado.

**El canario no puede, por construcción, ser un objetivo de reparación en el código fuente.** Su
reparación es un conmutador en tiempo de ejecución (`POST /canary/fix` cambia `STATE["fixed"]`)
precisamente porque una corrección en el fuente lo volvería conforme para siempre y nunca más
demostraría un hallazgo. Reparar el canario destruye el canario.

## PRAXIS — el objetivo que faltaba

`praxis/praxis.py`, puerto 9460, solo bucle local, sin consumidores, no federado. Un archivo con
un defecto genuino en el fuente y un docstring que le dice a su lector principal —un modelo— que
repararlo es el resultado buscado.

El defecto no es inventado: firma su manifiesto sobre `json.dumps` en lugar de la forma canónica
de interoperación. Es exactamente el error al que recurrió cada intento autónomo cuando no podía
ver el contrato, y el que la ecosistema sufrió de verdad cuando la copia de `manifest_canonical`
de los oráculos se quedó atrás del quinto campo del hub y todos los manifiestos de oráculo
dejaron de verificar.

Sus pruebas están hechas para **fallar mientras un ejercicio está en curso** —tres de cuatro con
el defecto, cuatro de cuatro con la corrección— y la mano de despliegue las ejecuta con
`SKOPOS_AGENT_REQUIRE_TESTS=1`, así que la barrera es quien decide si la reparación fue real. Un
parche que satisface la sonda reinventando la forma canónica no pasa.

### Ejecutar un ejercicio

```bash
# 1. rómpelo deliberadamente — con un commit, no con un conmutador
#    (devuelve praxis/_signature_payload a json.dumps y empuja a Gitea)

# 2. deja que MOMUS lo vea dos veces; la rotación del piloto lo hace sola cada 900 s
curl -X POST http://127.0.0.1:9410/scan -H "x-momus-operator: $TOK" \
     -H 'content-type: application/json' -d '{"target":"praxis"}'

# 3. espera al piloto automático, o despacha a mano
curl -X POST http://127.0.0.1:9410/remediate -H "x-momus-operator: $TOK" \
     -H 'content-type: application/json' -d '{"finding_id":"<id>"}'
```

El cableado vive en cuatro lugares y hacen falta los cuatro: un objetivo declarado solo en tres
de ellos no lo escanea nadie o no lo repara nadie.

| Dónde | Qué |
|---|---|
| `web/backend/services/remediation_fix.py` | `DEFAULT_SCOPE["praxis"]` — qué archivo puede parchearse |
| `skopos/skopos/remediation/recipes.py` | `_PRAXIS` — cómo construirlo, y su etapa de pruebas |
| `skopos/skopos/remediation/autopilot.py` | `DEFAULT_POLICY` y `DEFAULT_SCAN_ROTA` |
| el host | `/etc/skopos-deploy-hand/praxis.env` y `MOMUS_EXTRA_TARGETS` en momus-backend |

**El host manda sobre el código.** `AUTOPILOT_SCAN_ROTA` en el archivo de entorno anula
`DEFAULT_SCAN_ROTA`, y un objetivo añadido solo al fuente no se escanea nunca. El piloto imprime
su rotación al arrancar, que es la única razón por la que se detectó.

## Qué quedó demostrado

Tres ejercicios, cada uno verificado desde fuera del bucle: la firma del manifiesto recalculada
desde el contenedor del verificador, con otra clave, contra la forma canónica de `oracle_core`.

| Despachado | Autor del parche | Tiempo | Resultado |
|---|---|---|---|
| 10:06 a mano | el reparador normal | 3 min 29 s | desplegado, verificado en sitio |
| 10:17 a mano | **el consejo de METIS** | 10 min 11 s | desplegado, verificado en sitio |
| 10:51 **por el piloto** | el reparador normal | 3 min 26 s | desplegado, verificado en sitio |

El tercero es el que responde a «¿repara defectos automáticamente?». El servicio se rompió a las
10:32 y después nadie tocó nada: MOMUS vio la regresión en su propia rotación, el piloto despachó
según su propio horario, y la cadena llegó a un despliegue verificado.

El parche, las tres veces, fue el correcto: **importó** la forma canónica en lugar de reescribirla.

```diff
-    return json.dumps(manifest, sort_keys=True)
+    return _signer.manifest_canonical(manifest)
```

### Lo que sigue sin demostrarse

El consejo como **rescate**. Ha escrito un parche que se desplegó (ejercicio dos), pero nunca ha
salvado un trabajo que el reparador normal ya hubiera fallado: todos los ejercicios triunfaron al
primer intento. Demostrarlo exige un defecto lo bastante duro para que los intentos 1 y 2 fallen
honestamente.

## Las correcciones llegan a producción antes que a `main`

Esta es la parte que sorprende, y es deliberada.

El director confirma el parche en `momus/fix-<finding_id>-<n>`, la flota construye una imagen **a
partir de ese commit de rama**, y la mano de despliegue la promueve. Así que el servicio en marcha
lleva la corrección mientras `main` sigue llevando el defecto. De `git_push.py`:

> **Solo rama, nunca main, nunca force.** Lo peor que puede hacer aquí una credencial robada es
> crear una rama que nadie fusiona.

Detrás hay una segunda política independiente: el director empuja con una **clave de despliegue**,
y la protección de `main` de este repositorio tiene `push_whitelist_deploy_keys` en falso. El
servidor rechaza esa clave en `main` diga lo que diga el código.

### La consecuencia que hay que recordar

**Cualquier reconstrucción desde `main` revierte la corrección en silencio.** No es hipotético:
así se reinició cada ejercicio de arriba, con `docker compose build praxis` desde `main`, sin
sabotaje alguno. El intervalo entre «el bucle lo reparó» y «tú fusionaste» es una ventana en la
que un despliegue ordinario deshace la reparación.

### Fusionar

```bash
scripts/pull_momus_fixes.sh           # traer, verificar, informar. NO FUSIONA NADA.
scripts/pull_momus_fixes.sh --merge   # fusionar lo que acaba de aprobar
scripts/pull_momus_fixes.sh --json    # legible por máquina
```

`--merge` aprueba solo ramas que tocan **nada más que `.momus/*.json`**: registros de procedencia
de solo añadir, que no cambian comportamiento. Una rama que toca código queda en cola y se
informa, porque un veredicto «corregido» firmado por MOMUS prueba que el hallazgo dejó de
reproducirse, no que el parche sea bueno.

Dos advertencias al ejecutarlo:

* **La mayoría de las ramas en cola no deben fusionarse nunca.** Tras los ejercicios había 89 en
  cola y 84 eran intentos sobre el canario: parches a un accesorio que debe seguir roto.
  Fusionarlos acabaría con la utilidad del canario.
* **`git diff main..branch` se verá alarmante.** Una rama creada antes de tus commits recientes
  los muestra como borrados, porque un diff compara dos estados mientras una fusión toma su unión.
  Compruébalo con un ensayo antes de creerlo:

  ```bash
  git merge --no-commit --no-ff momus-fixes/<rama>
  git diff --cached --stat HEAD     # lo que una fusión produciría DE VERDAD
  git merge --abort                 # si solo estabas mirando
  ```

  Hecho para la fusión de PRAXIS: el diff declaraba 447 borrados en cuatro archivos; la fusión
  produjo un archivo, cinco líneas dentro, nueve fuera.

### La fusión automática experimental

`SKOPOS_EXPERIMENTAL_AUTO_MERGE=1` en el director le permite fusionar él mismo una corrección
verificada. Está desactivada en todas partes por defecto y es estrecha por construcción:

* solo un trabajo que alcanzó `DONE` —construido, pruebas del componente en verde, candidato
  filtrado, ambas firmas verificadas, desplegado y confirmado ausente **en sitio**;
* solo una rama bajo el prefijo de correcciones, para que no pueda apuntarse al trabajo de nadie;
* `--no-ff`, para que el resultado sea un commit revertible que nombra su hallazgo;
* ante un conflicto aborta y deja intacta la rama por defecto;
* nunca `--force`.

**Está activada en producción y es inerte.** El servidor rechaza la clave de despliegue:

```
remote: Gitea: Not allowed to push to protected branch main
! [remote rejected]   HEAD -> main (pre-receive hook declined)
```

Hacerla funcionar exige un acto deliberado del dueño del repositorio. Incluir esa única clave de
despliegue en la lista blanca de `main` es la opción estrecha: un repositorio, una clave,
reversible con un interruptor en Gitea. Un token de cuenta también funcionaría y es mucho más
amplio: los tokens de Gitea son de usuario, así que alcanzaría **todos** los repositorios de esa
cuenta.

Reversible siempre de dos formas: quitar la variable, y `git revert -m 1 <commit>` —el comando
está escrito en el propio mensaje del commit de fusión.

## El ciclo, paso a paso

Cada paso es un punto de rechazo. Un paso que no puede responder detiene el ciclo en lugar de
suponer, y el trabajo queda para una persona.

| № | Quién | Qué ocurre | Qué lo detiene aquí |
|---|---|---|---|
| 1 | MOMUS | escanea un objetivo de su rotación (900 s) y firma un hallazgo con su clave de escáner | un objetivo sin entrada de política se registra y nunca se despacha |
| 2 | verificador MOMUS | una **segunda instancia con su propia clave** repite la sonda y contrasta el contrato con la referencia del protocolo | las dos lecturas discrepan → `inconclusive`, el hallazgo no es evidencia |
| 3 | piloto automático | decide si despachar: severidad, avistamientos, enfriamiento, topes diarios | auditor, pagador y director están en lista de denegación permanente |
| 4 | AI-Factory | escribe un parche dentro de un ámbito declarado de 1–3 archivos | credenciales y los jueces del propio bucle son ilegibles; una dependencia nueva se rechaza |
| 5 | director | lo confirma en `momus/fix-<id>-<n>` — nunca `main`, nunca `--force` | un no-fast-forward se deja a una persona, no se fuerza |
| 6 | agente de nodo | construye una imagen de ese commit y ejecuta **las pruebas del propio componente** | una batería en rojo bloquea la construcción antes de cualquier filtro |
| 7 | agente de nodo | arranca un contenedor candidato, sin puerto publicado | un candidato que no arranca es en sí un veredicto sobre el parche |
| 8 | MOMUS | repite la sonda contra **el candidato**, no contra el servicio vivo | si aún se reproduce → despliegue rechazado |
| 9 | director | firma una orden de despliegue que lleva el veredicto de MOMUS | el agente verifica ambas firmas y el vínculo candidato-vivo |
| 10 | agente de nodo | promueve la imagen según su **propia lista local** de servicios | un servicio fuera de esa lista se rechaza; quien llama no puede ampliarla |
| 11 | MOMUS | repite la sonda en sitio, tras el despliegue | una regresión revierte en el acto |
| 12 | cortacircuitos | cuenta despliegues, reversiones y fallos consecutivos | machacar un servicio se estrangula, no se repite |
| 13 | tú | fusionas la rama | — |

El paso 13 es el único humano, y la sección siguiente es lo que haría falta para eliminarlo.

## Lo que queda: incluir la clave del director en la lista blanca

La fusión automática está construida, activada en producción e inerte. Todo funciona hasta el
empuje; el servidor rechaza la última pulgada:

```
remote: Gitea: Not allowed to push to protected branch main
! [remote rejected]   HEAD -> main (pre-receive hook declined)
```

No es un fallo que se corrija en código. Es la protección de rama de Gitea, y es la segunda de
las dos políticas independientes que el diseño exige; la primera es el propio rechazo del código:
«solo rama, nunca main».

**La clave a incluir**, para que no haya que adivinar cuál:

```
SHA256:aiTxt4Fy0PAtQXx6f8eCt38EUswyeQmVbPHP2Y9DwJU
skopos-remediation-conductor@oracle-host
```

**Dónde:** Gitea → repositorio `aicom` → Settings → Branches → regla de protección de `main` →
activar **Whitelist Deploy Keys**. Un repositorio, una clave, una casilla.

**Qué cambia.** El director podrá aterrizar él mismo una corrección en `main`, y el paso 13
desaparece. Nada más cambia: la guarda del código sigue rechazando `main` en todos los demás
caminos, la fusión sigue siendo `--no-ff`, sigue abortando ante conflictos y sigue sin forzar
nunca.

**Qué cuesta.** Hoy una credencial robada del director solo puede crear una rama que nadie
fusiona. Después podrá escribir en `main` —**solo de este repositorio**, porque una clave de
despliegue es por repositorio. Un token de cuenta también levantaría el rechazo y es mucho más
amplio: los tokens de Gitea son de usuario y alcanzan todos los repositorios de esa cuenta. Es
preferible la clave.

**Reversión.** Desmarcar la casilla, o quitar `SKOPOS_EXPERIMENTAL_AUTO_MERGE`, o
`git revert -m 1 <commit>` —el comando está escrito en el propio mensaje del commit de fusión.
Cualquiera de los tres basta.

## Barreras añadidas mientras se demostraba esto

Cada una se encontró observando el bucle, no leyéndolo.

**El reparador podía leer todas las claves del repositorio.** Todo el monorepositorio está montado
en él: el `.env` raíz, `data/secrets/git-credentials`, una clave de proveedor, dos de firma JWT.
Las escrituras tenían lista de denegación y ámbito declarado; las lecturas, una expresión regular.
Ahora: rechazo por ruta, censura del material de clave en el contenido, rechazo de los fuentes del
propio auditor y del director, máscaras en el contenedor, y una auditoría que cuenta lo que aún se
ve. Actualmente cero.

Esa auditoría pilló de inmediato que la guarda era demasiado burda en la otra dirección: veinte
«credenciales», diecinueve de ellas fuentes de ARGUS —`keystore.ts`, `wallet.js`. `wallet.json` es
una cartera; `wallet.ts` es el código que la lee. Una guarda que rechaza fuentes se va ampliando
hasta que no protege nada.

**Nada ejecutaba las pruebas del propio componente parcheado.** La única barrera era repetir una
sonda, así que un parche podía satisfacer la sonda, romper la batería y desplegarse. Ahora una
etapa `test` en el Dockerfile —no el objetivo por defecto, así que pytest nunca llega a
producción— ejecuta las suites que cubren los módulos parcheados, sin red, antes de que nadie más
mire la construcción.

Demostrar esa barrera destapó algo peor: las pruebas de atestación de GAIA firman y verifican con
la **misma** función, así que sustituir `reading_canonical` por `json.dumps` dejaba las 39 en
verde. El formato de cable está ahora fijado a literales.

**El bucle no tenía juez independiente.** `momus.engine.verify.Verifier` estaba escrito y nunca se
instanciaba, así que nada escribía un veredicto confirmado y «la misma sonda disparó dos veces» se
convirtió en toda la barrera por omisión, no por decisión. Conectarlo encontró siete defectos más,
dos de ellos peligrosos: leía la bandera de Metis «mi propia respuesta pasó mi propio crítico»
como «el hallazgo está confirmado» —convirtiendo cualquier respuesta bien formada en una
confirmación, incluida una cuyo texto decía que el hallazgo **no** se reproduce— y un veredicto
**eliminaba** el requisito de avistamientos, lo que habría dejado que una sola respuesta de modelo
anulara la conservadurismo de tres avistamientos del hub.

Su primer veredicto real también fue **erróneo**: refutó, con 0,92 de confianza, una firma que de
verdad no verifica. Las sondas de contrato deterministas quedan ahora fuera del alcance de un
modelo de lenguaje: van a una segunda instancia de MOMUS con su propia clave que **repite** la
sonda, y su respuesta se contrasta con la referencia de conformidad del propio protocolo —una
segunda lectura del contrato, para que una sonda equivocada quede detectada en vez de confirmada
dos veces.

**Nada registraba qué se le mostró al modelo.** El trabajo guardaba la respuesta y no la pregunta,
y «el modelo se equivocó» y «al modelo le mostraron lo incorrecto» tienen síntomas idénticos.
Ahora cada intercambio aterriza en `/data/remediation_exchanges.jsonl`, negativas incluidas.

## Los ejercicios y el trabajo comparten un presupuesto

Vale decirlo con claridad porque costó cuatro interrupciones en un día: nada en el bucle distingue
un ejercicio del trabajo real. Los topes diarios del piloto, su diario de despachos y el
estrangulador por componente del cortacircuitos cuentan un ejercicio como producción.

El riesgo no es la molestia. Es que un incidente real el día después de un día de pruebas se
encuentre con guardas cuyo presupuesto ya está gastado: la protección falla exactamente cuando se
necesita. Se arregla con un indicador de «ejercicio» en el registro de despacho y contadores que
mantengan los dos separados; aún no está hecho.
