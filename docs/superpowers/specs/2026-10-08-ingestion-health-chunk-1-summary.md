# Ingestion Health — Résumé du chunk 1

> Résumé de `2026-10-08-ingestion-health-chunk-1-brainstorm.md`.
> Plan d'implémentation : `docs/superpowers/plans/2026-10-07-ingestion-health-chunk-1.md`.
> Issue #18305, Notion TAS-1415, RFC 0001.

## En une phrase

Derrière le flag `INGESTION_HEALTH`, chaque connecteur déployé affiche un **chip de santé**. Ce chunk livre le circuit complet à sa taille minimale : **1 check de configuration**, **1 check de fonctionnement**, l'affichage dans l'UI, et **aucune notification**.

## Périmètre

- **Inclus :** tous les connecteurs déployés, quel que soit leur type, gérés par le composer ou self-hosted.
- **Exclus :**
  - les connecteurs built-in (import CSV, validation de draft, queues internes, jumeaux des feeds) ;
  - les feeds et les syncs, qui viendront dans un chunk suivant ;
  - les notifications (chunk 2) ;
  - `TOKEN_EXPIRED` ;
  - toute modification de l'authentification.

## Deux axes indépendants

|                  | Fonctionnement : `NO_HEARTBEAT`                            | Configuration : `USER_NOT_SERVICE_ACCOUNT` |
|------------------|------------------------------------------------------------|--------------------------------------------|
| Calculé par      | le manager, à chaque période (60 s par défaut, modifiable) | un resolver, à chaque appel API            |
| Stocké           | oui, dans Elasticsearch                                    | jamais                                     |
| Change le statut | oui                                                        | jamais                                     |
| Affiché          | partout : liste, cartes, page détail                       | page détail uniquement                     |

## Statuts

- **`stopped`** : un connecteur géré, arrêté par une personne. Ce statut l'emporte sur tous les autres.
- **`critical`** : aucun ping depuis 5 min ou plus, soit le même seuil que Active/Inactive.
- **`unknown`** : tous les autres cas.
- **Jamais `healthy`** dans ce chunk : un ping prouve que le connecteur est vivant, pas que les données arrivent.

## La règle du ping

- **Ce qui est surveillé :** seuls les connecteurs qui pinguent toutes les 40 s (le thread de ping pycti). Il faut que le manager ait vu **3 pings d'affilée, chacun à 2 périodes ou moins du précédent, avec un minimum de 120 s**. Avec la période par défaut, cela donne 120 s.
- **Pourquoi :** environ 30 connecteurs run-and-terminate « legacy » (par exemple `cape`) ne le déclarent pas. Ils pinguent une ou deux fois par run, puis se taisent pendant des heures : sans ce garde-fou, ils passeraient en rouge entre chaque run.
- **Panne du manager de plus de 2 périodes (au moins 120 s) :** les compteurs sont figés au lieu d'être remis à zéro, grâce à la clé Redis `ingestion-health-manager-last-run`. Un connecteur qui meurt juste après la panne est donc quand même détecté.
- **Jamais évalués :** les connecteurs qui déclarent `run_and_terminate`, et ceux qu'on n'a jamais vus tourner.

## Fonctionnement

1. Le manager, avec son propre lock, est le **seul à évaluer** et le **seul à appeler Redis**. Il tourne toutes les **60 s par défaut**. Cette période se règle dans la configuration (`ingestion_health_manager:interval`).
2. Quand le statut, le résumé ou les checks changent, il les écrit sur le connecteur dans Elasticsearch, sans toucher à `updated_at`.
3. Le champ `since` change uniquement quand le statut de santé change.
4. L'API lit ce verdict stocké et calcule le warning de configuration à la volée.
5. Le front affiche un chip FDS et une tooltip. La tooltip contient le résumé du serveur, en anglais et tel quel.
6. **Flag off :** strictement rien ne change par rapport à `master`.
7. **Tests d'intégration :** le manager est désactivé dans `config/test.json`.

## Risques acceptés

- **`updated_at` ne bouge pas que sur un ping.** Une édition ou un rapport du composer le modifie aussi, ce qui peut provoquer un faux `critical` sur un connecteur legacy.
- **Manager arrêté.** Le statut stocké vieillit sans que l'UI le montre.
- **Décalage.** Le chip passe en rouge jusqu'à une période (60 s par défaut) après « Inactive ». Plus la période est longue, plus ce décalage augmente, et plus un nouveau connecteur met de temps à être surveillé (environ 3 périodes).
- **Connecteur déjà mort à l'activation du flag.** Il n'est pas détecté : rien ne le distingue d'un connecteur legacy entre deux runs.
- **Jobs run-and-terminate planifiés toutes les 2 périodes ou moins** (2 min avec la période par défaut). Ils peuvent passer en faux `critical`. Ce risque grandit avec la période.
- **Restes après désactivation.** Si on désactive le flag après l'avoir activé, les clés Redis et les champs stockés restent en place.

## À la fin du chunk

- Mettre à jour le RFC 0001.
- Ouvrir 3 issues de suivi :
  - `TOKEN_EXPIRED` sans toucher à l'authentification ;
  - la révocation suspectée du token composer entre connecteurs qui partagent un user ;
  - un timestamp de ping dédié.
- Cocher le chunk 1 dans Notion.
