# LinkedIn API Test Bench

Application locale Python pour diagnostiquer l'accès à l'API LinkedIn via OAuth2 Authorization Code (3-legged), exécuter un catalogue d'endpoints, et générer des rapports détaillés.

## Fonctionnalités

- OAuth2 LinkedIn 3-legged avec `state` anti-CSRF.
- Callback local FastAPI pour échanger `code -> access_token`.
- Stockage local du token:
  - **chiffré** si `TOKEN_ENCRYPTION_KEY` est défini,
  - sinon stockage JSON en clair avec avertissement explicite.
- Catalogue d'endpoints configurable via `endpoints.json`.
- Runner `/run` pour lancer un sous-ensemble d'endpoints (`names`) ou tous (`all=true`).
- Rapport JSON horodaté dans `reports/` avec:
  - endpoint, méthode, status code,
  - body (JSON ou texte),
  - headers pertinents (request-id, rate limit),
  - latence, taille de réponse,
  - erreurs + suggestion de diagnostic (ex: scope manquant pour 403).
- UI HTML minimale sur `/`.

## Arborescence

- `app.py` : FastAPI, routes OAuth/UI/runner/report.
- `linkedin_client.py` : config, OAuth client, API client, token/state store.
- `endpoints.json` : catalogue d'endpoints à tester.
- `.env.example` : variables d'environnement nécessaires.
- `requirements.txt` : dépendances minimales.
- `reports/` : créé automatiquement.

## Prérequis

- Python 3.11+
- Une app LinkedIn Developer configurée avec redirect URI correspondant.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Renseignez ensuite vos secrets dans `.env`:

- `LINKEDIN_CLIENT_ID`
- `LINKEDIN_CLIENT_SECRET`
- `LINKEDIN_REDIRECT_URI`
- `LINKEDIN_SCOPES`
- (optionnel) `TOKEN_ENCRYPTION_KEY`

## Lancement

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Puis ouvrir <http://localhost:8000>.

## Utilisation rapide

1. Cliquez sur **Login with LinkedIn** (`/auth/login`).
2. Autorisez l'app LinkedIn.
3. LinkedIn redirige vers `/auth/callback` qui stocke le token.
4. Lancez les tests:
   - Tous les endpoints activés:
     ```bash
     curl -X POST http://localhost:8000/run -H "Content-Type: application/json" -d '{"all": true}'
     ```
   - Un sous-ensemble:
     ```bash
     curl -X POST http://localhost:8000/run -H "Content-Type: application/json" -d '{"names": ["profile_me"]}'
     ```
5. Consultez le rapport via le lien sur `/` ou `/reports/<fichier>.json`.

## Structure du catalogue `endpoints.json`

Chaque entrée supporte:

- `name` (string)
- `method` (`GET|POST|PUT|DELETE`)
- `url` (string)
- `headers` (object, optionnel)
- `params` (object, optionnel)
- `body_template` (object JSON, optionnel)
- `required_scopes` (liste informative)
- `enabled` (bool)

> Note: les `required_scopes` sont informatifs; l'API peut refuser selon les produits LinkedIn réellement approuvés.

## Erreurs gérées

- `401 Unauthorized` → token invalide/expiré.
- `403 Forbidden` → **"scope manquant ou accès produit non approuvé"**.
- `404 Not Found` → endpoint potentiellement incorrect/inaccessible.
- `429 Too Many Requests` → rate limit (inspecter `retry-after`).
- timeouts/réseau → retries limités et message d'erreur.
- réponse non-JSON → fallback sur texte brut.

## Sécurité

- Aucun secret hardcodé.
- Secrets chargés via `.env` (`python-dotenv`).
- Token masqué dans les retours (`xxxx...yyyy`).
- Pour chiffrement local, définissez `TOKEN_ENCRYPTION_KEY`.

## Limites & troubleshooting

- LinkedIn peut refuser des endpoints même avec un scope déclaré si le produit n'est pas approuvé.
- Vérifiez que `LINKEDIN_REDIRECT_URI` est exactement celui configuré côté LinkedIn Developer.
- Si token chiffré mais clé absente/changée, lecture impossible (message explicite).
- Les refresh tokens ne sont pas inventés: pris en charge uniquement s'ils sont réellement renvoyés.
