# Exploiter la boucle d'auto-réparation : clés, réglages et ce qu'il faut redéployer

> 🌐 [English](self-healing-operations.md) · [Русский](self-healing-operations.ru.md) · [Español](self-healing-operations.es.md) · **Français** · [中文](self-healing-operations.zh.md)

> **Le faire fusionner seul** — une case, avec schémas : [switch-to-auto-merge.fr.md](switch-to-auto-merge.fr.md).

> **Prouvé de bout en bout** — la cible d'entraînement, les trois exercices et pourquoi un correctif atteint la production avant `main` : [proving-the-loop.fr.md](proving-the-loop.fr.md).

> **Ce qui arrête un mauvais correctif** — chaque garde-fou que traverse une réparation sans surveillance, et l'incident derrière chacun : [autonomous-repair-guards.fr.md](autonomous-repair-guards.fr.md).

MOMUS trouve un bogue, l'AI-Factory écrit un correctif, la flotte le compile, MOMUS le soumet à sa porte de déploiement, un agent de nœud le publie, et une régression le restaure. Cette page est le côté opérateur : quel service tourne où, quelle variable d'environnement déclenche quel refus, et — la question qui a motivé cette page — **combien de choses faut-il redéployer quand on change le code.**

## La réponse courte sur les redéploiements

**Un seul.** Pas deux fabriques.

La route de rédaction des correctifs (`POST /api/remediation/fix`) n'est montée **que** là où `AIFACTORY_REMEDIATION_FIX_ENABLED=1`. Sur l'instance publique cette variable n'est pas définie, donc la route n'y existe pas du tout — et non « existe mais refuse ». La distinction est volontaire : `web/frontend/next.config.js` réécrit `/api/:path*` vers l'API interne, si bien qu'une route simplement désactivée resterait un point d'entrée publiquement accessible répondant 403 : une nouvelle surface d'attaque pour rien.

Donc :

| Ce que vous avez changé | Ce que vous redéployez |
|---|---|
| `web/backend/api/remediation.py`, `web/backend/services/remediation_fix.py` | uniquement l'**instance de remédiation** |
| `skopos/skopos/remediation/*` | le **chef d'orchestre** (`skopos-remediation`) |
| `momus/momus/*` | **momus-backend** |
| le code de compilation/déploiement de l'agent de nœud | l'**agent** sur chaque hôte de la flotte |
| `core/`, `llm/` partagés | les instances qui vous importent réellement — c'était déjà vrai pour chaque satellite de ce monorepo et la remédiation n'y change rien |

La fabrique publique n'exécute pas de remédiation, donc les changements de remédiation ne peuvent pas l'affecter.

## Les deux modes

Chaque composant surveillé par la boucle est dans l'un de deux modes, et la différence tient à une
seule étape, la dernière. Le début est identique : MOMUS sonde, confirme un constat, signe un
ticket de remédiation, le chef d'orchestre fait rédiger un correctif par la fabrique, et le
correctif atterrit sur une branche `momus/fix-…` sous forme de diff relisible.

**Autoréparation.** Une main de déploiement pour ce composant construit la branche, MOMUS rejoue
la sonde contre le candidat, et seul un verdict `fixed` signé promeut l'image et recrée le
service. Personne n'est réveillé. C'est le mode d'un composant qui a une main installée et une
image que cette main sait construire.

**Correctif seul.** Tout ce qui précède se produit, sauf la dernière étape : la branche est prête
et le travail attend. Un humain relit le diff et le déploie. Ce n'est pas un mode dégradé — c'est
le bon partout où une main n'aurait rien à promouvoir, et celui à choisir là où l'on veut lire le
correctif avant qu'il ne s'exécute.

Le mode d'un composant est une propriété de son déploiement, pas un réglage à retenir :

| composant | mode | pourquoi |
|---|---|---|
| canari | autoréparation | le terrain d'essai de la boucle ; il existe pour être cassé et réparé |
| gaia | autoréparation | projet compose propre, construit depuis ce dépôt |
| hub (production) | autoréparation | sa main atteint le relais de flotte ; voir *Qui tourne où* |
| oracles | correctif seul | construit depuis un autre checkout : aucune main ne peut produire son image |
| MOMUS, Treasury, SKOPOS, la porte | aucun | refusés dans le code — voir *Confinement* |

**Passer un composant en correctif seul** est une propriété de sa main ; trois leviers, par
sévérité croissante :

* `SKOPOS_AGENT_DRY_RUN=1` — la main vérifie l'ordre et imprime la commande qu'elle exécuterait.
  Tout l'amont continue : c'est le mode pour exercer la boucle sans rien déplacer.
* `SKOPOS_AGENT_SERVICE_ALLOWLIST=` (vide) — la main refuse tout ordre. De quoi garer un hôte sans
  toucher au reste de la flotte.
* `systemctl stop skopos-deploy-hand@<composant>` — les ordres s'accumulent chez le chef
  d'orchestre et expirent.

**Passer toute la boucle** : `SKOPOS_REMEDIATION_DRY_RUN=1` sur le chef d'orchestre — constats,
tickets et correctifs continuent, et rien n'est jamais ordonné.

Aucun levier ne transforme correctif-seul en autoréparation pour un composant sans main. C'est
délibéré : un composant devient autoréparable parce qu'il a un endroit où être déployé, pas parce
qu'on l'a marqué ainsi.

## Qui tourne où

| Rôle | Service | Écoute sur |
|---|---|---|
| trouve les bogues et sert de **porte de déploiement** | `momus-backend` | loopback |
| verse les primes (clé distincte que MOMUS ne détient jamais) | `momus-treasury` | loopback |
| orchestre une tâche de remédiation | `skopos-remediation` | loopback |
| rédige les correctifs | l'instance de remédiation de la fabrique | loopback |
| dépôt git distant (transport **et** piste d'audit) | Gitea `alexar76/aicom` | loopback (`:3000` HTTP, `:2222` SSH) |
| compile et publie | l'agent de nœud sur l'hôte cible | sortant uniquement, aucun port |
| ce qu'on casse et répare en premier | `momus-canary` | loopback |

Rien ici n'ouvre de port entrant sur un hôte de la flotte. L'agent interroge ; on ne l'appelle jamais.

## La chaîne, et la raison d'être de chaque étape

```
MOMUS trouve ──constat signé (A2A)──▶ chef d'orchestre
  ├─ 1. la fabrique rédige un DIFF unifié      (jamais une image ; elle ne compile pas)
  ├─ 2. le chef d'orchestre valide et pousse momus/fix-<finding_id>
  │        la branche est LE transport vers le compilateur ET l'artefact qu'un humain relit
  ├─ 3. l'ordre de compilation signé nomme un COMMIT   (jamais du code en ligne)
  │        l'agent : le récupère, refuse toute branche hors de SA liste de préfixes, refuse un
  │        commit qui n'est pas la pointe de cette branche, compile avec SA propre recette,
  │        annonce l'EMPREINTE, et démarre <service>-candidate pour donner à la porte quoi sonder
  ├─ 4. MOMUS sonde le CANDIDAT                (avant promotion, lié à cette empreinte)
  ├─ 5. l'ordre de déploiement signé porte l'empreinte
  │        l'agent : note l'empreinte en cours, déplace l'étiquette compose vers la nouvelle,
  │        recrée, applique la porte de santé, et vérifie que le conteneur EST bien cette empreinte
  ├─ 6. MOMUS réexamine le service EN PRODUCTION
  └─ 7. si cela se reproduit encore → ordre de restauration signé → l'agent remet l'empreinte notée
```

Deux omissions faisaient de tout ceci du théâtre, et elles méritent d'être connues car les symptômes trompaient :

* **Personne ne compilait d'image.** Donc « déployer » recréait le conteneur depuis l'image déjà présente sur l'hôte, la porte examinait précisément la compilation qu'elle prétendait remplacer, répondait à juste titre « se reproduit toujours », et l'escalade accusait le correctif.
* **`DeployOrder.image` n'était lu par personne.** Le champ existait et portait une valeur.

## Confinement : l'ordre dit *lequel*, l'hôte dit *ce qui est permis*

Chaque contrainte ci-dessous est appliquée par l'**agent**, depuis sa configuration locale. L'appelant ne peut en élargir aucune.

* l'agent ne compile et ne déploie que les services de son propre `SKOPOS_AGENT_SERVICE_ALLOWLIST` ;
* il ne compile que depuis des branches correspondant à son propre `SKOPOS_AGENT_BRANCH_PREFIXES` ;
* il ne compile qu'avec le Dockerfile et le contexte de son propre `SKOPOS_AGENT_BUILD_MAP` ;
* il ne déploie que des images **qu'il a compilées lui-même, pour ce même service** (vérifié contre son propre journal de compilations) — un ordre nommant toute autre image de l'hôte ne résout donc vers rien ;
* il refuse de promouvoir une image nouvelle sur un verdict qui a examiné le service *en production*. `gated` est à l'intérieur du FixVerdict signé, donc impossible à réétiqueter sur le réseau ;
* un ordre de restauration **ne porte aucune image** : il nomme un ordre antérieur, et la cible provient de ce que l'agent a noté comme actif avant ce déploiement. La voie de restauration ne peut donc rien publier de nouveau, et c'est pourquoi elle peut se passer du verdict MOMUS qu'un déploiement direct exige (on restaure précisément quand ce verdict s'est révélé faux).

`main` est protégée côté serveur **et** le chef d'orchestre refuse de pousser hors de son préfixe de branche. Deux politiques indépendantes, parce qu'une seule mal configurée ne doit pas suffire.

> **Vérifiez-le avant de vous y fier.** La protection de `main` sur `alexar76/aicom` a aujourd'hui `enable_push=true` avec la liste `['alexar76']`. Tout ce qui pousse *en tant que cet utilisateur* peut donc atteindre `main` directement. Poussez avec une **clé de déploiement** propre au dépôt, pas un jeton d'accès utilisateur (les jetons Gitea sont liés à l'utilisateur : `write:repository` couvre tous les dépôts du propriétaire). `push_whitelist_deploy_keys` vaut `false`, donc une clé de déploiement n'atteint pas `main`.
>
> À propos de la preuve : **ne** testez pas en poussant réellement vers `main` sur un hôte où un exécuteur Gitea Actions est installé — une poussée vers `main` peut déclencher un flux de déploiement. Lisez plutôt la configuration de protection.

## Réglages

### L'instance de remédiation de la fabrique

| Variable | Défaut | Rôle |
|---|---|---|
| `AIFACTORY_REMEDIATION_FIX_ENABLED` | non définie | **L'interrupteur principal.** Non définie ⇒ la route n'est pas montée du tout. |
| `AIFACTORY_REMEDIATION_KEY` | non définie | Secret partagé avec le chef d'orchestre. Obligatoire en production ; non définie en production ⇒ 503, jamais ouvert. |
| `AIFACTORY_REMEDIATION_MOMUS_PUBKEY` | non définie | La clé Ed25519 de MOMUS. Sans elle un constat ne peut être vérifié et toute requête est refusée. |
| `AIFACTORY_REMEDIATION_SCOPE` | canari + hub | JSON `{composant: [chemins]}`. Les **seuls** fichiers qu'un correctif pour ce composant peut toucher. Un modèle répondant par un chemin hors liste est refusé. Le hub est limité à `aimarket-hub/aimarket_hub/unpaid_invoke.py`. MOMUS / Treasury / la porte en sont absents. |
| `AIFACTORY_REMEDIATION_LLM_BUDGET_S` | `240` | La route demande le contenu complet des fichiers, donc cela prend des minutes, pas des secondes. Doit rester EN DESSOUS du délai du client du chef d'orchestre. |
| `AIFACTORY_DEMO_READONLY` | — | Si `1`, la rédaction de correctifs est refusée : c'est le garde-fou de la démo publique, et une démo publique n'est pas la place d'un correcteur autonome. |

### Le chef d'orchestre

| Variable | Défaut | Rôle |
|---|---|---|
| `SKOPOS_REMEDIATION_ENABLED` | `1` | Interrupteur principal. `0` ⇒ aucun ordre de déploiement n'est jamais signé. |
| `SKOPOS_REMEDIATION_DRY_RUN` | `0` | `1` ⇒ la chaîne s'exécute et ne signe rien qui parte. Et le dit franchement : la tâche se clôt en indiquant que rien n'a été déployé. Le mode réel (`0`) est la valeur par défaut pour canary + hub. |
| `SKOPOS_FACTORY_URL` | non définie | Non définie **en mode réel** est une faute de configuration, pas une valeur de repli : cela provoquait auparavant la synthèse d'un faux correctif. |
| `SKOPOS_MOMUS_PUBKEY` | non définie | Obligatoire hors dry-run : un constat invérifiable est refusé. |
| `SKOPOS_GIT_REPO_URL` / `SKOPOS_GIT_SSH_KEY` | non définies | Le dépôt distant de la branche de correctif et son identifiant (une clé de déploiement). |
| `SKOPOS_FIX_BRANCH_PREFIX` | `momus/fix-` | Aussi le préfixe hors duquel le chef d'orchestre refuse de pousser. |
| `SKOPOS_AGENT_TOKEN` | non définie | Le jeton d'enrôlement que présente la main de déploiement. Sans lui le chef d'orchestre ne distribue aucun ordre hors dry-run (fail-closed), et la main reçoit 503 indéfiniment. |
| `SKOPOS_DEPLOY_RESULT_TIMEOUT_S` | `420` | Combien de temps attendre le rapport de l'agent. Doit dépasser son intervalle d'interrogation + le délai de compose + l'attente de santé. |
| `SKOPOS_MAX_DEPLOYS_PER_DAY` | `6` | Étranglement. Atteint ⇒ refus, le coupe-circuit ne se déclenche **pas**. |
| `SKOPOS_MAX_DEPLOYS_PER_COMPONENT_PER_DAY` | `2` | Redéployer un même service en boucle est de l'agitation, pas de la remédiation. |
| `SKOPOS_MAX_ROLLBACKS` | `2` | **Le signal qui compte.** Deux restaurations dans la fenêtre ⇒ le coupe-circuit se déclenche. |
| `SKOPOS_MAX_ROLLBACK_RATE` | `0.34` | Avec `SKOPOS_BREAKER_MIN_SAMPLE` (`5`), car 1 sur 1 n'est pas un taux d'échec de 100 %. |
| `SKOPOS_MAX_CONSECUTIVE_FAILURES` | `3` | Confier à un humain un composant qu'on n'arrive pas à réparer. |
| `SKOPOS_OPERATOR_TOKEN` | non définie | Nécessaire pour réarmer un coupe-circuit déclenché. Non définie ⇒ personne ne peut, ce qui est la direction sûre. |

### L'agent de nœud

| Variable | Défaut | Rôle |
|---|---|---|
| `SKOPOS_AGENT_DRY_RUN` | `0` | `1` ⇒ valide et imprime la commande, sans rien exécuter. Le mode réel (`0`) est la valeur par défaut. |
| `SKOPOS_AGENT_SERVICE_ALLOWLIST` | `canary,hub` | Séparé par des virgules. Non défini ⇒ canary + hub (et leurs alias compose). Vide ⇒ l'agent ne peut toucher à rien. MOMUS / Treasury n'y figurent pas. |
| `SKOPOS_AGENT_BRANCH_PREFIXES` | `momus/fix-` | Local. Compiler depuis `main` reviendrait à compiler ce que quelqu'un a fusionné en dernier. |
| `SKOPOS_AGENT_BUILD_MAP` | `{}` | JSON `{service: {dockerfile, context, image_ref, network, compose_service}}`. Pas de recette ⇒ refus de compiler ce service. **`compose_service` est obligatoire là où le nom du composant et celui du service compose diffèrent** — MOMUS nomme sa cible `canary` alors que le service compose est `momus-canary`, et sans ce mappage chaque déploiement viserait un service inexistant. |
| `SKOPOS_AGENT_REPO_URL` | non définie | D'où le code peut venir. Jamais lu depuis un ordre. |
| `SKOPOS_AGENT_HEALTH_WAIT_S` | `20` | Combien de temps un conteneur a pour prouver qu'il ne redémarre pas en boucle. Un `compose up` sortant avec 0 n'est pas un verdict. |

## L'observer et l'arrêter

* `GET /remediation/health` — les chiffres, plus l'état et les seuils du coupe-circuit.
* `GET /metrics` — Prometheus. L'alerte qui compte est **`skopos_remediation_rollback_rate`** : restaurations par correctif publié, c'est-à-dire la fréquence à laquelle le verdict de la porte et la réalité divergent. Un correctif que la porte refuse ne coûte rien ; un correctif publié puis restauré est la forme dangereuse.
* `GET /api/remediation/stats` — le condensé que lit LOGOS. Ne renommez pas ses clés.
* `POST /remediation/breaker/clear` avec `x-skopos-operator` — la **seule** façon de réarmer un coupe-circuit déclenché. Rien dans le code ne le réarme : un coupe-circuit qui se réinitialiserait au redémarrage serait vaincu par la boucle de plantages même qu'il existe pour interrompre, et « ça s'est rétabli tout seul » est indiscernable de « personne n'a rien su ». Un déclenchement survit à un redémarrage, et un fichier d'état illisible échoue en position fermée.

## L'activer, dans l'ordre défendable

1. Définissez `AIFACTORY_REMEDIATION_*` sur l'instance **privée** et vérifiez que `GET /api/remediation/fix/status` affiche `enabled: true` et la portée attendue.
2. Donnez au chef d'orchestre son identifiant git et **prouvez que `main` refuse une poussée** avant de lui faire confiance.
3. Lancez l'agent de nœud. Les défauts sont en direct : `SKOPOS_AGENT_DRY_RUN=0` et `SKOPOS_AGENT_SERVICE_ALLOWLIST=canary,hub`. MOMUS / Treasury n'y figurent pas.
4. Confirmez que `/remediation/health` indique dry-run désactivé et que l'agent réclame les ordres.
5. Cassez le canari exprès, observez la boucle le réparer et le redéployer, et relisez la branche qu'elle a poussée.
6. Hub est déjà sur le même chemin. Un verdict `fixed` ne fusionne toujours pas vers `main`.
7. Pour parquer : `SKOPOS_AGENT_DRY_RUN=1` et `SKOPOS_REMEDIATION_DRY_RUN=1`, ou vider la liste.

Les constats visant le noyau de sécurité (MOMUS, la Treasury, la porte elle-même) ne prennent pas cette voie du tout : `escalation_for` les dirige vers la gouvernance humaine plus un vérificateur exploité de façon indépendante, car un auditeur qui se répare lui-même a certifié son propre travail.
