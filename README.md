# bsf-auth

Service d'authentification partagé entre les trois produits du programme B-School Factory : Portail, Référentiel de compétences et Passeport Digital. Il porte les **comptes**, les **rôles** et l'émission des **jetons**.

> **État : prototype de faisabilité validé.** Le spike [BSF-9](https://bschool.atlassian.net/browse/BSF-9) a démontré le flux OpenID Connect complet le 02/11/2026 (8 tests automatisés, 0 échec). La décision **D-019** est passée de « proposée » à « validée ». Ce dépôt contient ce prototype, **pas encore le service** : voir [« Ce que le prototype ne fait pas »](#ce-que-le-prototype-ne-fait-pas) avant de construire dessus.

## Ce que le service fournit

- Comptes et rôles communs aux trois produits.
- **Authentification unique (SSO)** : une seule page de connexion, hébergée ici, pour les trois produits. Un utilisateur déjà connecté sur l'un obtient son jeton sur les autres sans ressaisir son mot de passe.
- Cycle de vie des comptes par **lien à usage unique** envoyé par e-mail : création de compte par un administrateur, et mot de passe oublié. Aucun mot de passe ne circule.
- Désactivation des comptes, jamais de suppression (traçabilité des décisions passées).

## Architecture

`bsf-auth` est un **fournisseur OpenID Connect** bâti sur Spring Authorization Server. Il émet des **jetons JWT signés en RS256** et publie sa clé publique sur un endpoint JWKS, afin que les autres produits **valident les jetons sans nous appeler** — notre disponibilité n'est pas un point de panne pour le programme.

La **page de connexion vit dans ce dépôt** (décision **D-040**), aux couleurs du Portail, et sert les trois produits. Ni formulaire dans le Portail, ni page servie par le Portail : les deux variantes perdent le SSO ou dépendent de cookies tiers.

### Pour les squads Référentiel et Passeport — valider un jeton

| Élément | Valeur |
|---|---|
| Découverte OIDC | `/.well-known/openid-configuration` |
| Clé publique (JWKS) | **`/.well-known/jwks.json`** — et non le chemin `/oauth2/jwks` par défaut du framework |
| Algorithme | RS256 |
| Type de client | **public**, sans secret, **PKCE obligatoire** (une application web ne peut pas garder de secret) |

Trois points à connaître avant d'implémenter votre validation :

1. **Les rôles sont dans le jeton d'accès, pas dans l'`id_token`** (claim `roles`, sans préfixe `ROLE_`). Si votre front les lit via `getIdentityClaims()` d'`angular-oauth2-oidc`, il ne trouvera rien : le jeton est valide, le claim est ailleurs.
2. **L'audience d'un jeton d'accès vaut le `client_id` du produit qui l'a demandé.** Un jeton obtenu par le Portail ne peut donc pas servir à appeler votre API si vous validez `aud`. La règle d'appel entre produits **n'est pas encore arrêtée** — elle est en cours d'arbitrage dans [BSF-11](https://bschool.atlassian.net/browse/BSF-11) et ADR-003. N'implémentez pas votre propre convention avant cette décision.
3. **Le claim `sub` n'est pas encore stable** : il vaut aujourd'hui l'identifiant de connexion et devra valoir l'**UUID v4** de l'utilisateur. Ne le stockez pas comme clé étrangère avant que le contrat soit publié.

Le **contrat OpenAPI** de ce service est publié dans [`bsf-contracts`](https://github.com/AsKing07/bsf-contracts), pas ici. Il fait foi sur tout ce qui précède ; ce tableau en est un résumé de courtoisie.

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| `backend/` | Service Spring Boot. Contient aujourd'hui le prototype du spike BSF-9 |
| `docs/` | Documentation technique, décisions d'architecture (ADR) |
| `.github/` | Modèle de pull request |

## Lancer le prototype

Prérequis : JDK 17 ou plus, Maven.

```bash
cd backend
mvn clean test                                  # 8 tests attendus, 0 échec
```

Pour le démarrer et voir la page de connexion dans un navigateur :

```bash
export BSF_SPIKE_USER_PASSWORD="<au choix>"     # bash/zsh
mvn spring-boot:run                             # http://127.0.0.1:9000
```

```powershell
$env:BSF_SPIKE_USER_PASSWORD="<au choix>"       # PowerShell
mvn spring-boot:run
```

L'application **refuse de démarrer sans ce mot de passe** : il n'y en a aucun dans le dépôt. Utilisateur fictif `alice.test`, rôle `PORTEUR`. Clients déclarés : `portail-spike` (retour `http://127.0.0.1:4200/callback`) et `referentiel-spike` (retour `http://127.0.0.1:4300/callback`). Après connexion directe, `/` répond 404 — normal, il n'y a pas de page d'accueil.

Les variables d'environnement visées par le service sont listées dans [`.env.example`](.env.example) ; copier ce fichier en `.env` en local, sans jamais le versionner.

## Ce que le prototype ne fait pas

À traiter avant d'en faire un service — ne pas supposer ces points acquis :

| Limite | Conséquence |
|---|---|
| Clé de signature **régénérée à chaque démarrage** | Tout redémarrage invalide les jetons émis. Il faut une clé persistante hors dépôt, avec rotation par `kid` |
| Utilisateurs, clients et autorisations **en mémoire** | Rien n'est persisté. Base PostgreSQL et migrations à faire ([BSF-53](https://bschool.atlassian.net/browse/BSF-53)) |
| Page de connexion **générée par Spring** | Anglais, hors charte, sans contrôle d'accessibilité. Page propre à maquetter ([BSF-30](https://bschool.atlassian.net/browse/BSF-30)) |
| **HTTP**, pas HTTPS | Valable en local seulement. Hors local : ADR-006 |
| Ni **client Angular**, ni vrai navigateur | CORS, `angular-oauth2-oidc` et la page `/callback` restent à éprouver ([BSF-10](https://bschool.atlassian.net/browse/BSF-10)) |
| Pas de **jetons de rafraîchissement**, pas de **déconnexion** | À décider dans ADR-003 ([BSF-54](https://bschool.atlassian.net/browse/BSF-54)) |

Les versions retenues par le prototype — Spring Boot 4.1.2, Spring Authorization Server via Spring Security 7 — **ne préjugent pas d'ADR-002** ([BSF-44](https://bschool.atlassian.net/browse/BSF-44)). Elles en sont une donnée d'entrée : le prototype montre que cette combinaison répond à notre besoin.

## Sécurité

Ce dépôt est **public** (décision D-038 : la protection de la branche principale n'est pas disponible sur un dépôt privé de compte gratuit). En conséquence, sans exception :

- Aucune clé privée, aucun mot de passe, aucun jeton dans le dépôt — **y compris dans une migration de base**.
- Aucun secret dans les journaux d'intégration continue.
- Les données de développement, de test et de démonstration sont **fictives**. Aucun nom réel de personne, aucune donnée d'entreprise.
- `main` est protégée : pull request obligatoire, une approbation, aucune poussée directe (D-036).

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md).

## Maintenance

Squad Portail. Le suivi du travail se fait dans le projet Jira `BSF`.
