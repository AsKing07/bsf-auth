# Contribuer

Ce dépôt suit une stratégie volontairement simple : des **branches courtes** et des **pull requests** vers `main`, qui est protégée.

## Branches

- `main` est protégée : **aucune poussée directe**.
- Une branche par ticket Jira, de courte durée : `feat/BSF-12-formulaire-depot`, `fix/BSF-30-redirection`, `docs/BSF-44-adr-002`, `chore/BSF-43-outillage`.
- Pas de Git Flow, pas de branche `develop`.

## Commits

Format [Conventional Commits](https://www.conventionalcommits.org/fr/v1.0.0/), avec **la clé Jira du ticket** (projet `BSF`) :

```
feat(subject): ajoute le formulaire de dépôt (BSF-12)
fix(auth): corrige la redirection après connexion (BSF-30)
docs: précise le lancement local (BSF-44)
```

Types usuels : `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`.

## Pull requests

1. Ouvrir la PR vers `main` en remplissant le modèle (ticket, changement, tests exécutés, impacts).
2. Demander une relecture **quand quelqu'un est disponible**. Un ticket traité à deux compte comme relecture. On n'attend pas indéfiniment.
3. La fusion se fait quand la CI est verte (dès qu'elle existe) et que le diff est propre.

## Ce qui ne doit jamais être versionné

- secrets, jetons, mots de passe, clés privées, fichiers `.env` (seul `.env.example` est versionné, **sans valeur réelle**) ;
- données personnelles réelles : les jeux de test et de démonstration sont **fictifs** ;
- artefacts de build, dépendances installées, dumps de base de données.

Un secret commité, même supprimé ensuite, reste dans l'historique : il faut alors le **révoquer**, pas seulement le retirer.

## Tests

On ne désactive jamais un test pour faire passer un pipeline. Une erreur attendue se teste, elle ne se contourne pas.
