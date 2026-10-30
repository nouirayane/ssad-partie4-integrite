# SSAD TP1 - Partie 4 : Authenticité / Intégrité

Python 3, bibliothèque standard uniquement (tkinter, hashlib, secrets).

## Contenu

| Fichier | Rôle |
|---------|------|
| `partie4/hachage.py` | SHA-256 écrit à la main + MD5, SHA-1, SHA-512, SHA3-256 ; effet avalanche |
| `partie4/rsa.py` | RSA à la main : clés publique/privée, signature et vérification |
| `partie4/hmac_dh.py` | Échange Diffie-Hellman et HMAC écrit à la main |
| `partie4/integrite.py` | Format du canal et vérification automatique par B |
| `app.py` | Interface Tkinter : onglets Intégrité et Hachage |
| `tests_partie4.py` | 18 tests unitaires et mesures de performance |

## Lancement

```
python app.py
python tests_partie4.py
```

## Principe

A hache le message puis prouve son intégrité avec une clé qui n'est jamais envoyée dans le canal :
- **Signature RSA** : A signe avec sa clé privée, B vérifie avec la clé publique de A.
- **HMAC + Diffie-Hellman** : A et B échangent leurs clés publiques et calculent chacun la même clé secrète.

Format du canal : `MODE|code_hash|message|preuve` (`SIG` ou `MAC`).
