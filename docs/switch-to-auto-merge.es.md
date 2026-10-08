# Cambiar el bucle para que fusione en `main` por sí mismo

> 🌐 [English](switch-to-auto-merge.md) · [Русский](switch-to-auto-merge.ru.md) · **Español** · [Français](switch-to-auto-merge.fr.md) · [中文](switch-to-auto-merge.zh.md)

El código está hecho y activado. **Solo queda una casilla en Gitea.**

## Qué hacer

1. Gitea → el repositorio **`aicom`** → **Settings → Branches**
2. Abrir la regla de protección de **`main`**
3. Marcar **Whitelist Deploy Keys**
4. Guardar

La clave que quedará permitida —la del director, y solo ella:

```
SHA256:aiTxt4Fy0PAtQXx6f8eCt38EUswyeQmVbPHP2Y9DwJU
skopos-remediation-conductor@oracle-host
```

Ya está puesto en el director, ahí no hay nada que cambiar:

```
SKOPOS_EXPERIMENTAL_AUTO_MERGE=1
SKOPOS_DEFAULT_BRANCH=main
```

### Comprobar que surtió efecto

```bash
docker exec skopos-remediation python3 -c "
from skopos.remediation.git_push import GitPusher
p = GitPusher()
r = p.merge_to_main(finding_id='<un hallazgo que llegó a DONE>',
                    branch='momus/fix-<id>-<n>', component='praxis')
print(r.ok, r.error or r.details)"
```

`ok: True` significa que el cambio está vivo. `Not allowed to push to protected branch main`
significa que Gitea aún no se ha modificado.

## Qué cambia

```mermaid
flowchart LR
    subgraph NOW["ahora"]
        direction TB
        A1["el trabajo llega a DONE"] --> B1["el director intenta fusionar"]
        B1 --> C1["Gitea rechaza<br/>la clave de despliegue"]
        C1 --> D1["la rama de corrección espera"]
        D1 --> E1["tú ejecutas<br/>pull_momus_fixes.sh"]
        E1 --> F1["main actualizado"]
    end
    subgraph AFTER["tras la casilla"]
        direction TB
        A2["el trabajo llega a DONE"] --> B2["el director fusiona solo"]
        B2 --> C2["merge --no-ff<br/>en main"]
        C2 --> F2["main actualizado"]
        F2 -.->|"si no era eso"| G2["git revert -m 1"]
    end
    NOW ~~~ AFTER
```

Solo eso. Todo lo demás queda igual: la fusión sigue siendo `--no-ff`, sigue abortando ante un
conflicto, sigue sin forzar nunca, y solo corre para un trabajo que alcanzó `DONE`.

## Qué cuesta y cómo deshacerlo

| | |
|---|---|
| **Hoy** una clave robada del director puede | crear una rama de corrección que nadie fusiona |
| **Después** podrá | escribir en `main` — **solo de este repositorio** (una clave de despliegue es por repositorio) |
| **No uses** en su lugar un token de cuenta | los tokens de Gitea son de usuario: alcanzan todos los repositorios de esa cuenta |

Tres vías independientes de vuelta, basta cualquiera:

* desmarcar la casilla en Gitea;
* `SKOPOS_EXPERIMENTAL_AUTO_MERGE=0` en el director;
* `git revert -m 1 <commit>` —el comando está escrito en el propio mensaje del commit de fusión.

## Por qué esto es un interruptor aparte

El código del director rechaza `main` en todos los caminos menos uno, y ese rechazo es lo que
mantiene una credencial robada como una molestia y no como un incidente. La protección de rama de
Gitea es una **segunda política, independiente**, sobre lo mismo. Habilitar la fusión significa
decidir levantar la segunda —por eso es una casilla que marcas tú, no una variable que el bucle
pueda ponerse a sí mismo.

## Cómo funciona la reparación misma

Cada rombo es un punto de rechazo. Un paso que no puede responder se detiene y deja el trabajo a
una persona; nunca supone.

```mermaid
flowchart TD
    A["MOMUS escanea un objetivo<br/>cada 900 s"] --> B{"¿hallazgo?"}
    B -->|no| A
    B -->|sí| C["segunda instancia de MOMUS,<br/>su propia clave: repite la sonda<br/>+ contrasta el contrato"]
    C --> D{"¿ambas lecturas<br/>coinciden en que es real?"}
    D -->|no| X1["inconcluso —<br/>no cuenta como evidencia"]
    D -->|sí| E{"política del piloto:<br/>severidad · avistamientos<br/>enfriamiento · topes diarios"}
    E -->|rechazado| X2["registrado, dejado a una persona"]
    E -->|despachar| F["AI-Factory: el reparador escribe<br/>un parche en 1–3 archivos declarados<br/>credenciales ilegibles"]
    F --> G["commit en la rama de corrección<br/>nunca main · nunca --force"]
    G --> H["orden de compilación:<br/>imagen desde ese commit"]
    H --> I{"¿pasan las pruebas<br/>propias del componente?"}
    I -->|no| X3["compilación bloqueada,<br/>el fallo va al siguiente intento"]
    I -->|sí| J["contenedor candidato,<br/>sin puerto publicado"]
    J --> K{"puerta previa a la promoción:<br/>MOMUS sondea al CANDIDATO"}
    K -->|sigue reproduciéndose| X4["despliegue rechazado"]
    K -->|corregido| L["el director firma<br/>la orden de despliegue<br/>con el veredicto de MOMUS"]
    L --> M{"el agente de nodo comprueba:<br/>ambas firmas<br/>+ SU propia lista de servicios"}
    M -->|no| X5["la mano de despliegue rechaza"]
    M -->|sí| BR{"cortacircuitos:<br/>despliegues · reversiones<br/>fallos consecutivos"}
    BR -->|"estrangulado"| X6["despliegue retenido:<br/>machacar no es reparar"]
    BR -->|"dentro del presupuesto"| N["promoción de la imagen"]
    N --> O{"puerta de despliegue en sitio,<br/>tras la instalación"}
    O -->|se reproduce| P["orden de reversión,<br/>en el acto"]
    O -->|limpio| Q["DONE"]
    Q --> R["fusión — hoy tú,<br/>tras la casilla el director"]
```

Dos hechos útiles mientras corre:

* **Los intentos 1 y 2 usan el reparador; el intento 3 usa el consejo de METIS** —la última
  barrera antes de que el trabajo pase a una persona
  (`AIFACTORY_REMEDIATION_COUNCIL_FROM_ATTEMPT=3`). Una deliberación cuesta unas 16 veces un
  intento normal; por eso va tercera y no primera.
* **Una reconstrucción desde `main` revierte la corrección en silencio** mientras la rama de
  corrección siga sin fusionar. Esa es la razón práctica para tomarse la casilla en serio en vez
  de dejar la rama en cola.

## Cerca de aquí

* [self-healing-operations.es.md](self-healing-operations.es.md) — claves, ajustes, qué se redespliega
* [autonomous-repair-guards.es.md](autonomous-repair-guards.es.md) — cada barrera y el incidente detrás
* [proving-the-loop.es.md](proving-the-loop.es.md) — el objetivo de práctica y los tres ejercicios verificados
