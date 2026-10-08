# Qué detiene un parche malo — las salvaguardas por las que pasa una reparación desatendida

> 🌐 [English](autonomous-repair-guards.md) · [Русский](autonomous-repair-guards.ru.md) · **Español** · [Français](autonomous-repair-guards.fr.md) · [中文](autonomous-repair-guards.zh.md)

> **Cambiarlo para que fusione solo** — una casilla, con diagramas: [switch-to-auto-merge.es.md](switch-to-auto-merge.es.md).

> **Demostrado de extremo a extremo** — el objetivo de práctica, los tres ejercicios y por qué una corrección llega a producción antes que a `main`: [proving-the-loop.es.md](proving-the-loop.es.md).

El **2026-08-29** el bucle cerró un ciclo sin nadie dentro: el autopiloto despachó según su propio
horario a las 13:58:33 y MOMUS confirmó la corrección en su sitio a las 14:02:15 — tres minutos
cuarenta y dos segundos, un contenedor real sustituido, verificado desde fuera del bucle por una
llamada no pagada por encima del techo que responde `402` en lugar de `200`.

Llegar hasta ahí costó dieciséis paradas distintas. Ninguna era visible leyendo el código; cada una
apareció porque una ejecución se detuvo. Esta página es en qué se convirtió cada una de ellas — las
salvaguardas por las que pasa ahora un parche, en el orden en que las encuentra, y el incidente
detrás de cada una. Léela como la respuesta a dos preguntas que un operador acabará haciéndose:
*qué detiene un parche malo* y *por qué se detuvo mi reparación*.

El hilo común: **no se publica nada que no se haya demostrado que arregla el fallo.** En ocho
ejecuciones consecutivas el bucle no promovió ni una sola vez un parche que no pasara su propia
puerta. Todo lo de abajo es o esa regla, o una forma de no desperdiciar una ejecución antes de
llegar a ella.

## Antes siquiera de gastar un tique

| Salvaguarda | Qué rechaza | Por qué existe |
|---|---|---|
| **Política de despacho** | un componente sin entrada, o una severidad por debajo de la suya | La omisión es un valor por defecto, y un valor por defecto es justo lo que una configuración ampliada sobrescribe sin que nadie lo note. Los componentes denegados (el auditor, el pagador, el director) se rechazan por nombre, no por ausencia. |
| **Frescura** (`AUTOPILOT_STALE_AFTER_S`) | un hallazgo que los escaneos más recientes ya no reproducen | `seen_count` es acumulativo y nunca baja, así que un bug arreglado hace semanas sigue pareciendo evidencia para siempre. Un hallazgo que ya nadie reproduce es un bug cerrado con muy buena memoria. |
| **Enfriamiento**, levantado para trabajos terminales | amontonar tiques sobre trabajo en curso | El enfriamiento protege el trabajo. Un trabajo que escaló no tiene ninguno, y un hallazgo que sigue reproduciéndose después de eso es exactamente el caso que merece otro intento. Las repeticiones siguen acotadas por los topes diarios, que son el instrumento correcto para «esto falla una y otra vez». |
| **Reembolso** (`AUTOPILOT_RECONCILE_WINDOW_S`) | gastar el presupuesto del día en un tique sobre el que nadie actuó | MOMUS responde `200` y la entrada A2A responde «trabajando» en cuanto acepta, porque el trabajo corre en segundo plano — la respuesta no puede decir en qué quedó. El autopiloto le pregunta al director, dentro de una ventana, si el trabajo arrancó de verdad. Preguntado sin límite de tiempo, un tique que alguien envía horas después justifica retroactivamente uno muerto. Un director inalcanzable no reembolsa nunca: reembolsar de más convierte un tope en ningún tope. |

## Mientras se redacta el parche

| Salvaguarda | Qué rechaza | Por qué existe |
|---|---|---|
| **Conflicto de interés** | un parche que toca `momus/momus/`, `treasury/`, `skopos/` o la propia puerta | Un bucle capaz de parchear lo que decide que un hallazgo es real puede decidir que no lo es. Impuesto en código tanto contra el mapa de alcance como contra la respuesta del modelo. |
| **Truncamiento** | una respuesta cortada en el límite de salida | `finish_reason` venía en la respuesta del proveedor y nadie la leía, así que un fichero cuya última cadena de comillas triples nunca se cerró se confirmó, se compiló y se lanzó. Se rechaza **incluso cuando el fragmento superviviente es sintácticamente válido**: el truncamiento es una propiedad de la respuesta, no del fragmento. |
| **Sintaxis** | un parche que no compila | `ast.parse` responde en milisegundos lo que el arranque de un contenedor respondía en noventa segundos — y respondía como «el candidato no arrancó», un mensaje con forma de problema de infraestructura para un fichero truncado. |
| **Dependencias** | un import que la compilación del componente no declara | Una compilación Docker solo copia fuente, así que un parche que añade una biblioteca compila limpiamente y muere al importar. La salvaguarda lee el Dockerfile / requirements / pyproject del componente: «no lo importa ninguno de los ficheros que puedo parchear» no es «no está instalado». |
| **Sin cambios** | un parche que no cambia nada | Informar de éxito ahí empujaría una rama vacía y haría que MOMUS sometiera a su puerta la compilación sin parchear. |

Cada rechazo de arriba **viaja al siguiente intento.** A temperatura 0 el mismo prompt devuelve el
mismo parche, así que un reintento que no sabe por qué falló el anterior es una repetición, no un
reintento — medido: tres diffs idénticos rechazados en ocho segundos.

## Mientras se publica

| Salvaguarda | Qué rechaza | Por qué existe |
|---|---|---|
| **Una rama libre, nunca forzar** | sobrescribir una rama de corrección | Un trabajo reabierto reinicia su presupuesto de intentos por diseño, así que `attempt` no puede servir de nombre único. El nombre se elige libre contra un espejo recién traído; forzar sigue prohibido, porque una rama de corrección divergente puede ser justo la que está leyendo una persona. |
| **La puerta previa a la promoción** | promover una compilación que MOMUS no ha confirmado | La sonda se repite **contra el candidato**, así que un veredicto `fixed` habla de lo que está a punto de publicarse y no del servicio sin parchear que sigue en marcha. |
| **Disponibilidad ante la puerta** (`SKOPOS_GATE_RETRIES`) | llamar «inalcanzable» a un servicio que todavía está arrancando | RUNNING no es LISTENING: el agente informa de una compilación en cuanto el contenedor está en pie. Solo se vuelve a preguntar por *inalcanzable* — un rechazo rechazará idéntico. |
| **Una puerta inconclusa no es un veredicto** | culpar al parche de una puerta que no pudo ejecutarse | Otro intento de la fábrica no puede arreglar una puerta que no arranca; dar vueltas quemaría el presupuesto y luego escalaría culpando a la corrección. |
| **El agente despliega solo lo que compiló** | una orden firmada que nombra una imagen que este agente no produjo | La autoridad está dividida a propósito: el director publica una orden y no puede ejecutarla; el agente ejecuta y no puede inventarse ninguna. |
| **Reversión ante regresión** | dejar en pie una promoción mala | La reverificación posterior al despliegue corre **después** de que el agente informe, no antes — una reverificación que compite con el intervalo de consulta describe la compilación que intentabas sustituir. |

## Cuando aun así no logra arreglarlo

Tres intentos, y después una persona. Dos palancas deciden cuánto valen esos intentos:

* **Escalar el modelo, no el contador** (`AIFACTORY_REMEDIATION_ESCALATION_MODEL`). A partir del
  intento 2 la ronda de reparación usa el modelo indicado. Sin definir significa la elección del
  propio enrutador — tres intentos con un modelo que no puede resolver un problema son tres
  fracasos del mismo tipo y ninguna información nueva.
* **Dale el contrato, no una descripción del contrato.** Una sonda que dice «tu firma no verifica»
  sin decir *qué* se firma le está pidiendo a alguien que reimplemente un contrato de
  interoperabilidad a partir de prosa, y cada intento lo reimplementó de otra manera. Las sondas
  declaran su criterio de aceptación, y allí donde una biblioteca compartida define el contrato el
  servicio la importa — una segunda copia se desvía el día en que la primera gana un campo.

## Lo que sigue siendo de una persona

* Los hallazgos contra el núcleo de seguridad — el auditor, la Treasury, la puerta — no toman esta
  vía en absoluto. Un auditor que se arregla a sí mismo ha certificado su propio trabajo.
* Fusionar una rama de corrección a `main`. Un veredicto `fixed` publica una imagen; no fusiona
  código.
* Qué contiene la imagen de un componente. El bucle puede arreglar código dentro de una imagen y no
  puede añadir jamás una dependencia por su cuenta: eso es una decisión de cadena de suministro.
* Rearmar un cortacircuitos disparado. Nada en el código lo rearma — un cortacircuitos que se
  reiniciase solo quedaría derrotado por el bucle de caídas que existe para interrumpir.

## Ajustes que introduce esta página

| Variable | Por defecto | Qué hace |
|---|---|---|
| `AUTOPILOT_CONDUCTOR_URL` | `http://127.0.0.1:9402` | Solo lectura, y solo para responder una pregunta: ¿el tique que enviamos puso en marcha algún trabajo? |
| `AUTOPILOT_RECONCILE_WINDOW_S` | `600` | Cuánto tiempo tiene un despacho para aparecer como trabajo antes de darlo por absorbido y reembolsarlo. |
| `AUTOPILOT_STALE_AFTER_S` | `2 ×` el intervalo de escaneo | Más viejo que esto sin reproducirse, y un hallazgo no es un defecto vivo. `0` desactiva la comprobación. |
| `SKOPOS_GATE_RETRIES` / `SKOPOS_GATE_RETRY_DELAY_S` | `6` / `5` | Medio minuto de margen de arranque para un candidato que el agente ya ha informado como en marcha. |
| `AIFACTORY_REMEDIATION_ESCALATION_MODEL` | sin definir | El modelo a usar del intento 2 en adelante. En qué modelo gastar es decisión del operador. |

## La lección que vale la pena conservar

Tres de las dieciséis paradas no eran defectos del bucle sino defectos de cómo se **comprobaba**:
una corrección que debía entregarle el contrato al modelo pareció terminada tres veces y no lo
estaba, hasta que se renderizó el prompt real en el receptor. Una comprobación de compilación corrió
contra el checkout equivocado. Un vigilante contó una entrada vieja del diario como si fuera nueva.

**Verifica una entrega en el receptor, nunca en el emisor.** Todo lo que hay aguas arriba puede
parecer correcto mientras no llega nada.
