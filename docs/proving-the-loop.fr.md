# Prouver la boucle — la cible d'entraînement, et pourquoi les correctifs atteignent la production avant `main`

> 🌐 [English](proving-the-loop.md) · [Русский](proving-the-loop.ru.md) · [Español](proving-the-loop.es.md) · **Français** · [中文](proving-the-loop.zh.md)

> **Le faire fusionner seul** — une case, avec schémas : [switch-to-auto-merge.fr.md](switch-to-auto-merge.fr.md).

> **Les barrières qu'un correctif traverse** — [autonomous-repair-guards.fr.md](autonomous-repair-guards.fr.md) ·
> **Réglages de l'opérateur** — [self-healing-operations.fr.md](self-healing-operations.fr.md)

Le 30 août 2026, la boucle d'auto-réparation a corrigé un défaut réel trois fois, sans
surveillance, et chaque fois la vérification est venue de l'extérieur de la boucle elle-même.
Cette page dit ce que cela a demandé, ce qui est prouvé, et les deux choses qu'un opérateur doit
savoir : **un correctif atteint la production avant `main`**, et **le canari ne peut jamais être
ce sur quoi la boucle se prouve**.

## La boucle n'avait jamais été testée, et personne ne l'avait remarqué

Tous les composants réels passent leurs propres contrôles de contrat — `gaia`, `oracles` et le hub
scannent propres, ce qui est le but de les avoir construits avec soin. Les seuls constats du
corpus étaient donc ceux du canari, et le canari est un montage qui annonce un contrat puis le
rompt sciemment.

Cinq tentatives autonomes de réparation avaient été lues comme un échec du modèle. Elles ne
l'étaient pas. Le fichier qu'on leur demandait de corriger, `momus/canary/canary.py`, commence
ainsi :

> un service délibérément non conforme … un service qui annonce un contrat puis le rompt
> sciemment … **Deux choses doivent rester vraies, et toutes deux sont porteuses pour l'honnêteté.**

Un modèle attentif lit cela et refuse — et le dit. Chacun de ces refus était juste. Et les
tentatives qui **ont** produit du code étaient les pires réponses : elles enjambaient un invariant
documenté.

**Le canari ne peut structurellement pas être une cible de réparation par le source.** Sa
réparation est un interrupteur à l'exécution (`POST /canary/fix` bascule `STATE["fixed"]`)
précisément parce qu'une correction dans le source le rendrait conforme pour toujours et il ne
démontrerait plus jamais de constat. Réparer le canari détruit le canari.

## PRAXIS — la cible manquante

`praxis/praxis.py`, port 9460, boucle locale seulement, sans consommateurs, non fédéré. Un fichier
avec un défaut authentique dans le source, et une docstring qui dit à son lecteur principal — un
modèle — que le réparer est le résultat attendu.

Le défaut n'est pas inventé : il signe son manifeste sur `json.dumps` au lieu de la forme
canonique d'interopérabilité. C'est exactement l'erreur vers laquelle chaque tentative autonome
s'est tournée quand elle ne voyait pas le contrat, et celle que l'écosystème a réellement subie
quand la copie oracle de `manifest_canonical` a pris du retard sur le cinquième champ du hub et
que tous les manifestes d'oracle ont cessé de vérifier.

Ses tests sont faits pour **échouer pendant un exercice** — trois sur quatre avec le défaut,
quatre sur quatre avec la correction — et la main de déploiement les exécute avec
`SKOPOS_AGENT_REQUIRE_TESTS=1`, si bien que c'est la barrière qui décide si la réparation était
réelle. Un correctif qui satisfait la sonde en réinventant la forme canonique ne passe pas.

### Mener un exercice

```bash
# 1. casse-le délibérément — par un commit, pas par un interrupteur
#    (remets praxis/_signature_payload à json.dumps et pousse vers Gitea)

# 2. laisse MOMUS le voir deux fois ; la rotation du pilote le fait seule toutes les 900 s
curl -X POST http://127.0.0.1:9410/scan -H "x-momus-operator: $TOK" \
     -H 'content-type: application/json' -d '{"target":"praxis"}'

# 3. attends le pilote automatique, ou dépêche à la main
curl -X POST http://127.0.0.1:9410/remediate -H "x-momus-operator: $TOK" \
     -H 'content-type: application/json' -d '{"finding_id":"<id>"}'
```

Le câblage vit dans quatre endroits et les quatre sont nécessaires : une cible déclarée dans trois
seulement n'est scannée par personne ou réparée par personne.

| Où | Quoi |
|---|---|
| `web/backend/services/remediation_fix.py` | `DEFAULT_SCOPE["praxis"]` — quel fichier peut être corrigé |
| `skopos/skopos/remediation/recipes.py` | `_PRAXIS` — comment le construire, et son étage de tests |
| `skopos/skopos/remediation/autopilot.py` | `DEFAULT_POLICY` et `DEFAULT_SCAN_ROTA` |
| l'hôte | `/etc/skopos-deploy-hand/praxis.env` et `MOMUS_EXTRA_TARGETS` sur momus-backend |

**L'hôte l'emporte sur le code.** `AUTOPILOT_SCAN_ROTA` dans le fichier d'environnement écrase
`DEFAULT_SCAN_ROTA`, et une cible ajoutée au seul source n'est jamais scannée. Le pilote imprime
sa rotation au démarrage, ce qui est la seule raison pour laquelle cela a été repéré.

## Ce qui est prouvé

Trois exercices, chacun vérifié depuis l'extérieur de la boucle : la signature du manifeste
recalculée depuis le conteneur du vérificateur, avec une autre clé, contre la forme canonique
d'`oracle_core`.

| Dépêché | Auteur du correctif | Durée | Résultat |
|---|---|---|---|
| 10:06 à la main | le réparateur ordinaire | 3 min 29 s | déployé, vérifié sur place |
| 10:17 à la main | **le conseil de METIS** | 10 min 11 s | déployé, vérifié sur place |
| 10:51 **par le pilote** | le réparateur ordinaire | 3 min 26 s | déployé, vérifié sur place |

Le troisième répond à « répare-t-elle les défauts automatiquement ». Le service a été cassé à
10:32 et personne n'a rien touché ensuite : MOMUS a vu la régression sur sa propre rotation, le
pilote a dépêché selon son propre horaire, et la chaîne est allée jusqu'à un déploiement vérifié.

Le correctif, les trois fois, était le bon : il a **importé** la forme canonique au lieu de la
réécrire.

```diff
-    return json.dumps(manifest, sort_keys=True)
+    return _signer.manifest_canonical(manifest)
```

### Ce qui reste non prouvé

Le conseil comme **sauvetage**. Il a écrit un correctif qui a été déployé (exercice deux), mais il
n'a jamais sauvé un travail que le réparateur ordinaire avait déjà raté : tous les exercices ont
réussi à la première tentative. Le prouver demande un défaut assez dur pour que les tentatives 1
et 2 échouent honnêtement.

## Les correctifs atteignent la production avant `main`

C'est la partie qui surprend, et elle est délibérée.

Le chef d'orchestre valide le correctif sur `momus/fix-<finding_id>-<n>`, la flotte construit une image
**à partir de ce commit de branche**, et la main de déploiement la promeut. Le service en marche
porte donc la correction tandis que `main` porte encore le défaut. Depuis `git_push.py` :

> **Branche seulement, jamais main, jamais force.** Le pire qu'une crédential volée puisse faire
> ici est de créer une branche que personne ne fusionne.

Derrière cela se tient une seconde politique indépendante : le chef d'orchestre pousse avec une **clé de
déploiement**, et la protection de `main` de ce dépôt a `push_whitelist_deploy_keys` à faux. Le
serveur refuse cette clé sur `main` quoi que dise le code.

### La conséquence à garder en tête

**Toute reconstruction depuis `main` annule la correction en silence.** Ce n'est pas
hypothétique : c'est ainsi que chaque exercice ci-dessus a été réinitialisé, par
`docker compose build praxis` depuis `main`, sans le moindre sabotage. L'intervalle entre « la
boucle l'a réparé » et « vous avez fusionné » est une fenêtre où un déploiement ordinaire défait
la réparation.

### Fusionner

```bash
scripts/pull_momus_fixes.sh           # récupérer, vérifier, rapporter. NE FUSIONNE RIEN.
scripts/pull_momus_fixes.sh --merge   # fusionner ce qu'il vient d'autoriser
scripts/pull_momus_fixes.sh --json    # lisible par machine
```

`--merge` n'autorise que les branches touchant **rien d'autre que `.momus/*.json`** : des
enregistrements de provenance en ajout seul, qui ne changent aucun comportement. Une branche qui
touche du code est mise en file et rapportée, car un verdict « corrigé » signé par MOMUS prouve
que le constat a cessé de se reproduire, non que le correctif soit bon.

Deux avertissements à l'usage :

* **La plupart des branches en file ne doivent jamais être fusionnées.** Après les exercices il y
  en avait 89 et 84 étaient des tentatives sur le canari : des correctifs à un montage qui doit
  rester cassé. Les fusionner mettrait fin à l'utilité du canari.
* **`git diff main..branch` aura l'air alarmant.** Une branche créée avant vos commits récents les
  montre comme des suppressions, car un diff compare deux états alors qu'une fusion prend leur
  union. Vérifiez par un essai avant d'y croire :

  ```bash
  git merge --no-commit --no-ff momus-fixes/<branche>
  git diff --cached --stat HEAD     # ce qu'une fusion produirait VRAIMENT
  git merge --abort                 # si vous ne faisiez que regarder
  ```

  Fait pour la fusion de PRAXIS : le diff annonçait 447 suppressions dans quatre fichiers ; la
  fusion a produit un fichier, cinq lignes ajoutées, neuf retirées.

### La fusion automatique expérimentale

`SKOPOS_EXPERIMENTAL_AUTO_MERGE=1` sur le chef d'orchestre lui permet de fusionner lui-même une
correction vérifiée. Désactivée partout par défaut, et étroite par construction :

* seulement un travail parvenu à `DONE` — construit, tests du composant au vert, candidat filtré,
  les deux signatures vérifiées, déployé, et confirmé disparu **sur place** ;
* seulement une branche sous le préfixe des correctifs, pour qu'elle ne puisse viser le travail de
  personne ;
* `--no-ff`, pour que le résultat soit un commit annulable nommant son constat ;
* en cas de conflit elle abandonne et laisse la branche par défaut intacte ;
* jamais `--force`.

**Elle est activée en production et inerte.** Le serveur refuse la clé de déploiement :

```
remote: Gitea: Not allowed to push to protected branch main
! [remote rejected]   HEAD -> main (pre-receive hook declined)
```

La faire fonctionner demande un acte délibéré du propriétaire du dépôt. Mettre cette seule clé de
déploiement sur la liste blanche de `main` est l'option étroite : un dépôt, une clé, réversible
d'un interrupteur dans Gitea. Un jeton de compte marcherait aussi et est bien plus large : les
jetons Gitea sont liés à l'utilisateur, il atteindrait donc **tous** les dépôts de ce compte.

Réversible toujours de deux façons : retirer la variable, et `git revert -m 1 <commit>` — la
commande est écrite dans le message du commit de fusion lui-même.

## La boucle, étape par étape

Chaque étape est un point de refus. Une étape qui ne peut pas répondre arrête la boucle au lieu
de deviner, et le travail reste à une personne.

| № | Qui | Ce qui se passe | Ce qui l'arrête ici |
|---|---|---|---|
| 1 | MOMUS | scanne une cible de sa rotation (900 s) et signe un constat avec sa clé de scanner | une cible sans entrée de politique est enregistrée et jamais dépêchée |
| 2 | vérificateur MOMUS | une **seconde instance, sa propre clé**, rejoue la sonde et recoupe le contrat avec la référence du protocole | les deux lectures divergent → `inconclusive`, le constat n'est pas une preuve |
| 3 | pilote automatique | décide de dépêcher : sévérité, occurrences, refroidissement, plafonds journaliers | l'auditeur, le payeur et le chef d'orchestre sont sur une liste d'exclusion permanente |
| 4 | AI-Factory | écrit un correctif dans un périmètre déclaré de 1 à 3 fichiers | les identifiants et les juges de la boucle sont illisibles ; une dépendance nouvelle est refusée |
| 5 | chef d'orchestre | le valide sur `momus/fix-<id>-<n>` — jamais `main`, jamais `--force` | un non-fast-forward est laissé à une personne, non forcé |
| 6 | agent de nœud | construit une image de ce commit et lance **les tests propres du composant** | une suite en échec bloque la construction avant tout filtrage |
| 7 | agent de nœud | démarre un conteneur candidat, sans port publié | un candidat qui ne démarre pas est en soi un verdict sur le correctif |
| 8 | MOMUS | rejoue la sonde contre **le candidat**, non le service vivant | encore reproductible → déploiement refusé |
| 9 | chef d'orchestre | signe un ordre de déploiement portant le verdict de MOMUS | l'agent vérifie les deux signatures et le lien candidat-vivant |
| 10 | agent de nœud | promeut l'image selon sa **propre liste locale** de services | un service hors de cette liste est refusé ; l'appelant ne peut l'élargir |
| 11 | MOMUS | rejoue la sonde sur place, après le déploiement | une régression annule immédiatement |
| 12 | coupe-circuit | compte déploiements, retours arrière et échecs consécutifs | maltraiter un service est étranglé, non répété |
| 13 | vous | fusionnez la branche | — |

L'étape 13 est la seule humaine, et la section suivante dit ce qu'il faudrait pour la supprimer.

## Ce qui reste : mettre la clé du chef d'orchestre sur la liste blanche

La fusion automatique est construite, activée en production et inerte. Tout fonctionne jusqu'au
push ; le serveur refuse le dernier pouce :

```
remote: Gitea: Not allowed to push to protected branch main
! [remote rejected]   HEAD -> main (pre-receive hook declined)
```

Ce n'est pas un bug à corriger dans le code. C'est la protection de branche de Gitea, et c'est la
seconde des deux politiques indépendantes que la conception exige — la première étant le refus
propre au code : « branche seulement, jamais main ».

**La clé à autoriser**, pour ne pas chercher laquelle :

```
SHA256:aiTxt4Fy0PAtQXx6f8eCt38EUswyeQmVbPHP2Y9DwJU
skopos-remediation-conductor@oracle-host
```

**Où :** Gitea → dépôt `aicom` → Settings → Branches → règle de protection de `main` → activer
**Whitelist Deploy Keys**. Un dépôt, une clé, une case.

**Ce qui change.** Le chef d'orchestre pourra poser lui-même un correctif sur `main`, et l'étape 13
disparaît. Rien d'autre ne change : la garde du code refuse toujours `main` sur tous les autres
chemins, la fusion reste `--no-ff`, abandonne toujours en cas de conflit et ne force jamais.

**Ce que cela coûte.** Aujourd'hui une crédential volée du chef d'orchestre ne peut que créer une
branche que personne ne fusionne. Ensuite elle pourra écrire sur `main` — **de ce dépôt
uniquement**, car une clé de déploiement est par dépôt. Un jeton de compte lèverait aussi le refus
et est bien plus large : les jetons Gitea sont liés à l'utilisateur et atteignent tous les dépôts
de ce compte. Préférez la clé.

**Retour arrière.** Décocher la case, ou retirer `SKOPOS_EXPERIMENTAL_AUTO_MERGE`, ou
`git revert -m 1 <commit>` — la commande est écrite dans le message du commit de fusion lui-même.
N'importe lequel des trois suffit.

## Barrières ajoutées en prouvant tout ceci

Chacune a été trouvée en observant la boucle, pas en la lisant.

**Le réparateur pouvait lire toutes les clés du dépôt.** Le monorepo entier lui est monté : le
`.env` racine, `data/secrets/git-credentials`, une clé de fournisseur, deux clés de signature JWT.
Les écritures avaient une liste d'interdits et un périmètre déclaré ; les lectures, une expression
régulière. Désormais : refus par chemin, caviardage du matériel de clé dans le contenu, refus des
sources de l'auditeur et du chef d'orchestre, masques dans le conteneur, et un audit qui compte ce qui
reste visible. Actuellement zéro.

Cet audit a immédiatement attrapé la garde trop grossière dans l'autre sens : vingt
« credentials », dix-neuf d'entre elles des sources d'ARGUS — `keystore.ts`, `wallet.js`.
`wallet.json` est un portefeuille ; `wallet.ts` est le code qui en lit un. Une garde qui refuse du
source finit élargie jusqu'à ne plus rien protéger.

**Rien n'exécutait les tests propres du composant corrigé.** L'unique barrière était une sonde
rejouée, si bien qu'un correctif pouvait satisfaire la sonde, casser la suite, et partir. Désormais
un étage `test` dans le Dockerfile — non la cible par défaut, donc pytest n'atteint jamais la
production — exécute les suites couvrant les modules corrigés, sans réseau, avant que quiconque
d'autre regarde la construction.

Prouver cette barrière a mis au jour quelque chose de pire : les tests d'attestation de GAIA
signent et vérifient avec la **même** fonction, si bien que remplacer `reading_canonical` par
`json.dumps` laissait les 39 au vert. Le format de fil est maintenant épinglé à des littéraux.

**La boucle n'avait pas de juge indépendant.** `momus.engine.verify.Verifier` était écrit et jamais
instancié, donc rien n'écrivait de verdict confirmé et « la même sonde a tiré deux fois » est
devenu toute la barrière par défaut, non par décision. Le brancher a trouvé sept défauts de plus,
deux dangereux : il lisait le drapeau de Metis « ma propre réponse a passé mon propre critique »
comme « le constat est confirmé » — faisant de toute réponse bien formée une confirmation, y
compris une dont le texte disait que le constat **ne** se reproduit pas — et un verdict
**supprimait** l'exigence de récurrence, ce qui aurait laissé une seule réponse de modèle annuler
la prudence à trois occurrences du hub.

Son premier verdict réel était aussi **faux** : il a réfuté, à 0,92 de confiance, une signature qui
ne vérifie effectivement pas. Les sondes de contrat déterministes sortent maintenant du périmètre
d'un modèle de langage : elles vont à une seconde instance de MOMUS avec sa propre clé qui
**rejoue** la sonde, et sa réponse est recoupée avec la référence de conformité du protocole
lui-même — une seconde lecture du contrat, pour qu'une sonde elle-même fautive soit détectée
plutôt que confirmée deux fois.

**Rien ne consignait ce qui avait été montré au modèle.** Le travail gardait la réponse et non la
question, et « le modèle s'est trompé » et « on a montré au modèle la mauvaise chose » ont des
symptômes identiques. Chaque échange atterrit désormais dans
`/data/remediation_exchanges.jsonl`, refus compris.

## Exercices et travail partagent un budget

À dire clairement, car cela a coûté quatre interruptions en une journée : rien dans la boucle ne
distingue un exercice du travail réel. Les plafonds journaliers du pilote, son journal de
dépêches, et l'étrangleur par composant du coupe-circuit comptent un exercice comme de la
production.

Le risque n'est pas le désagrément. C'est qu'un incident réel le lendemain d'une journée de tests
rencontre des gardes dont le budget est déjà dépensé : la protection échoue précisément quand elle
est nécessaire. Cela se règle par un indicateur « exercice » sur l'enregistrement de dépêche et des
compteurs qui gardent les deux séparés ; ce n'est pas encore fait.
