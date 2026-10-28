# bsf-auth

Service d'authentification partagé entre les trois produits du programme B-School Factory : Portail, Référentiel de compétences et Passeport Digital. Il porte les **comptes**, les **rôles** et l'émission des **jetons**.

> **État : amorçage.** Le dépôt est créé (ticket BSF-43). Il ne contient pas encore de code.

## Ce que le service fournit

- Comptes et rôles communs aux trois produits.
- Cycle de vie des comptes par **lien à usage unique** envoyé par e-mail : création de compte par un administrateur, et mot de passe oublié. Aucun mot de passe ne circule.
- Désactivation des comptes, jamais de suppression (traçabilité des décisions passées).

## Cible d'architecture et condition

La cible est un **véritable SSO** : `bsf-auth` agit en fournisseur OpenID Connect (Spring Authorization Server), avec une **page de connexion centralisée**, des **jetons JWT signés**, et la clé publique exposée sur un endpoint JWKS (`/.well-known/jwks.json`) pour que les autres produits valident les jetons sans nous appeler.

Cette cible est **conditionnée au spike BSF-9**. S'il échoue, on se replie sur un compte partagé sans session partagée, et **la page de connexion est retirée de ce dépôt**.

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| `backend/` | Service Spring Boot |
| `docs/` | Documentation technique, décisions d'architecture (ADR) |
| `.github/` | Modèle de pull request |

## Lancer le projet

Rien à lancer à ce jour. Les variables d'environnement attendues sont listées dans [`.env.example`](.env.example) ; copier ce fichier en `.env` en local, sans jamais le versionner.

## Contrat d'API

Le contrat OpenAPI de ce service est publié dans `bsf-contracts`, pas ici.

## Sécurité

- Aucune clé privée, aucun mot de passe, aucun jeton dans le dépôt.
- Les données de développement et de démonstration sont **fictives**.

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md).

## Maintenance

Squad Portail. Le suivi du travail se fait dans le projet Jira `BSF`.
