# Ce qui arrête un mauvais correctif — les garde-fous que traverse une réparation sans surveillance

> 🌐 [English](autonomous-repair-guards.md) · [Русский](autonomous-repair-guards.ru.md) · [Español](autonomous-repair-guards.es.md) · **Français** · [中文](autonomous-repair-guards.zh.md)

> **Le faire fusionner seul** — une case, avec schémas : [switch-to-auto-merge.fr.md](switch-to-auto-merge.fr.md).

> **Prouvé de bout en bout** — la cible d'entraînement, les trois exercices et pourquoi un correctif atteint la production avant `main` : [proving-the-loop.fr.md](proving-the-loop.fr.md).

Le **2026-08-29**, la boucle a fermé un cycle sans personne dedans : l'autopilote a dispatché selon
son propre horaire à 13:58:33 et MOMUS a confirmé le correctif en place à 14:02:15 — trois minutes
quarante-deux secondes, un vrai conteneur remplacé, vérifié depuis l'extérieur de la boucle par un
appel non payé au-dessus du plafond répondant `402` au lieu de `200`.

Y parvenir a demandé seize arrêts distincts. Aucun n'était visible à la lecture du code ; chacun est
apparu parce qu'une exécution s'est arrêtée. Cette page est ce que chacun d'eux est devenu — les
garde-fous que traverse désormais un correctif, dans l'ordre où il les rencontre, et l'incident
derrière chacun. Lisez-la comme la réponse à deux questions qu'un opérateur finira par poser :
*qu'est-ce qui arrête un mauvais correctif*, et *pourquoi ma réparation s'est-elle arrêtée*.

Le fil conducteur : **rien n'est livré sans qu'on ait montré que cela répare le défaut.** Sur huit
exécutions consécutives, la boucle n'a pas promu une seule fois un correctif qui n'avait pas passé sa
propre porte. Tout ce qui suit est soit cette règle, soit un moyen de ne pas gâcher une exécution
avant de l'atteindre.

## Avant même qu'un ticket soit dépensé

| Garde-fou | Ce qu'il refuse | Pourquoi il existe |
|---|---|---|
| **Politique de dispatch** | un composant sans entrée, ou une sévérité inférieure à la sienne | Une omission est une valeur par défaut, et une valeur par défaut est justement ce qu'une configuration élargie écrase sans qu'on le remarque. Les composants refusés (l'auditeur, le payeur, le chef d'orchestre) le sont par leur nom, pas par leur absence. |
| **Fraîcheur** (`AUTOPILOT_STALE_AFTER_S`) | un constat que les derniers scans ne reproduisent plus | `seen_count` est cumulatif et ne redescend jamais, si bien qu'un bogue corrigé il y a des semaines continue éternellement de passer pour une preuve. Un constat que plus personne ne reproduit est un bogue clos doté d'une longue mémoire. |
| **Cool-down**, levé pour les travaux en état terminal | empiler des tickets sur un travail en cours | Le cool-down protège un travail en cours. Un travail qui a escaladé n'en a plus, et un constat qui se reproduit encore après cela est exactement le cas qui mérite un nouvel essai. Les répétitions restent bornées par les plafonds journaliers, qui sont le bon instrument pour « ça continue d'échouer ». |
| **Remboursement** (`AUTOPILOT_RECONCILE_WINDOW_S`) | dépenser le budget du jour sur un ticket que personne n'a traité | MOMUS répond `200` et l'entrée A2A répond « en cours » dès l'instant où elle accepte, parce que le travail s'exécute en arrière-plan — la réponse ne peut pas dire ce qu'il en est advenu. L'autopilote demande au chef d'orchestre, dans une fenêtre, si un travail a réellement commencé. Posée sans borne, la question laisse un ticket envoyé des heures plus tard justifier rétroactivement un ticket mort. Un chef d'orchestre injoignable ne rembourse jamais : trop rembourser transforme un plafond en absence de plafond. |

## Pendant que le correctif s'écrit

| Garde-fou | Ce qu'il refuse | Pourquoi il existe |
|---|---|---|
| **Conflit d'intérêts** | un correctif touchant à `momus/momus/`, `treasury/`, `skopos/`, ou à la porte elle-même | Une boucle capable de corriger ce qui décide qu'un constat est réel peut décider qu'il ne l'est pas. Appliqué dans le code, à la fois contre la carte de portée et contre la réponse du modèle. |
| **Troncature** | une réponse coupée à la limite de sortie | `finish_reason` était dans la réponse du fournisseur et n'était pas lu, si bien qu'un fichier dont la dernière chaîne entre triples guillemets ne se fermait jamais a été commité, compilé et lancé. Elle est refusée **même quand le fragment survivant s'analyse correctement** : la troncature est une propriété de la réponse, pas du fragment. |
| **Syntaxe** | un correctif qui ne compile pas | `ast.parse` répond en millisecondes à ce qu'un démarrage de conteneur répondait en quatre-vingt-dix secondes — et répondait sous la forme « le candidat n'a pas démarré », un message en forme de panne d'infrastructure pour un fichier tronqué. |
| **Dépendances** | un import que la compilation du composant ne déclare pas | Une compilation Docker ne fait que copier les sources, si bien qu'un correctif qui ajoute une bibliothèque se compile sans erreur et meurt à l'import. Le garde-fou lit les Dockerfile / requirements / pyproject du composant : « pas importé par les fichiers que j'ai le droit de corriger » n'est pas « pas installé ». |
| **Correctif sans effet** | un correctif qui ne change rien | Annoncer un succès à cet endroit pousserait une branche vide et ferait passer par la porte de MOMUS la compilation non corrigée. |

Chaque refus ci-dessus **est transmis à la tentative suivante.** À température 0, le même prompt
renvoie le même correctif : une reprise qui ignore pourquoi la précédente a échoué est une
répétition, pas une reprise — mesuré : trois diffs rejetés identiques en huit secondes.

## Pendant la livraison

| Garde-fou | Ce qu'il refuse | Pourquoi il existe |
|---|---|---|
| **Une branche libre, jamais un force** | l'écrasement d'une branche de correctif | Un travail rouvert réinitialise son budget de tentatives par conception, donc `attempt` ne peut pas servir de nom unique. Le nom est choisi libre contre un miroir fraîchement récupéré ; le forçage reste refusé, car une branche de correctif divergente peut être celle qu'un humain est en train de lire. |
| **La porte de pré-promotion** | promouvoir une compilation que MOMUS n'a pas confirmée | La sonde est rejouée **contre le candidat**, si bien qu'un verdict « corrigé » porte sur ce qui est sur le point d'être livré, et non sur le service non corrigé encore en marche. |
| **Disponibilité avant la porte** (`SKOPOS_GATE_RETRIES`) | traiter d'« injoignable » un service encore en train de démarrer | RUNNING n'est pas LISTENING : l'agent annonce une compilation dès que le conteneur est levé. Seul *injoignable* est redemandé — un refus refusera à l'identique. |
| **Une porte non concluante n'est pas un verdict** | accuser le correctif d'une porte qui n'a pas pu s'exécuter | Une nouvelle tentative de la Factory ne peut pas réparer une porte qui refuse de s'exécuter ; boucler brûlerait le budget puis escaladerait en accusant le correctif. |
| **L'agent ne déploie que ce qu'il a compilé** | un ordre signé nommant une image que cet agent n'a pas produite | L'autorité est scindée à dessein : le chef d'orchestre publie un ordre et ne peut pas l'exécuter ; l'agent exécute et ne peut pas en inventer un. |
| **Restauration en cas de régression** | laisser en place une mauvaise promotion | Le réexamen après déploiement s'exécute **après** que l'agent a rendu compte, pas avant — un réexamen qui court contre l'intervalle d'interrogation décrit la compilation que l'on cherchait à remplacer. |

## Quand elle n'y arrive toujours pas

Trois tentatives, puis un humain. Deux leviers décident de ce que valent ces tentatives :

* **Escaladez le modèle, pas le compteur** (`AIFACTORY_REMEDIATION_ESCALATION_MODEL`). À partir de
  la tentative 2, la passe de réparation utilise le modèle nommé. Non définie ⇒ le choix propre du
  routeur — trois tentatives avec un seul modèle incapable de résoudre un problème sont trois échecs
  de même nature et aucune information nouvelle.
* **Donnez-lui le contrat, pas une description du contrat.** Une sonde qui dit « votre signature ne
  se vérifie pas » sans dire *ce qui* est signé demande de réimplémenter un contrat
  d'interopérabilité à partir de prose, et chaque tentative l'a réimplémenté différemment. Les
  sondes énoncent leur critère d'acceptation, et là où une bibliothèque partagée définit le contrat,
  le service l'importe — une seconde copie dérive le jour où la première gagne un champ.

## Ce qui reste à un humain

* Les constats visant le noyau de sécurité — l'auditeur, la Treasury, la porte — ne prennent pas
  cette voie du tout. Un auditeur qui se répare lui-même a certifié son propre travail.
* Fusionner une branche de correctif vers `main`. Un verdict `fixed` livre une image ; il ne fusionne
  pas de code.
* Ce que contient l'image d'un composant. La boucle peut corriger du code à l'intérieur d'une image
  et ne peut jamais ajouter une dépendance de son propre chef : c'est une décision de chaîne
  d'approvisionnement.
* Réarmer un coupe-circuit déclenché. Rien dans le code ne le réarme — un coupe-circuit qui se
  réinitialiserait au redémarrage serait vaincu par la boucle de plantages qu'il existe pour
  interrompre.

## Les réglages introduits par cette page

| Variable | Défaut | Rôle |
|---|---|---|
| `AUTOPILOT_CONDUCTOR_URL` | `http://127.0.0.1:9402` | En lecture seule, et seulement pour répondre à une question : le ticket que nous avons envoyé a-t-il démarré un travail ? |
| `AUTOPILOT_RECONCILE_WINDOW_S` | `600` | Combien de temps un dispatch a pour apparaître sous forme de travail avant d'être déclaré absorbé et remboursé. |
| `AUTOPILOT_STALE_AFTER_S` | `2 ×` l'intervalle de scan | Plus vieux que cela sans se reproduire, et un constat n'est pas un défaut vivant. `0` désactive le contrôle. |
| `SKOPOS_GATE_RETRIES` / `SKOPOS_GATE_RETRY_DELAY_S` | `6` / `5` | Une demi-minute de marge de démarrage pour un candidat que l'agent a déjà annoncé comme en marche. |
| `AIFACTORY_REMEDIATION_ESCALATION_MODEL` | non définie | Le modèle à utiliser à partir de la tentative 2. Sur quel modèle dépenser est une décision d'opérateur. |

## La leçon à retenir

Trois des seize arrêts n'étaient pas des défauts de la boucle mais des défauts dans la façon dont
elle était **contrôlée** : un correctif censé livrer un contrat au modèle a semblé fait trois fois
sans l'être, jusqu'à ce que le prompt réel soit rendu chez le destinataire. Un contrôle de
compilation s'exécutait contre le mauvais checkout. Un observateur comptait une vieille entrée de
journal pour une entrée fraîche.

**Vérifiez une livraison chez le destinataire, jamais chez l'expéditeur.** Tout ce qui se trouve en
amont peut sembler correct alors que rien n'arrive.
