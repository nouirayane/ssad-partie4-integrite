# SSAD TP1 - Partie 4 : Intégrité avec SHA-256

Python 3, bibliothèque standard uniquement (tkinter).

## Principe

- A chiffre le message (César, Hill ou Playfair de la partie 2) : `C`.
- A calcule `H = SHA256(C)` et envoie `C` et `H` dans le canal.
- B reçoit `C'`, recalcule `H' = SHA256(C')` et compare les empreintes.
- B ne déchiffre que si `H = H'` ; sinon le déchiffrement est bloqué.

La clé de chiffrement n'est jamais envoyée dans le canal.

## Contenu

| Fichier | Rôle |
|---------|------|
| `partie4/hachage.py` | SHA-256 écrit entièrement à la main |
| `partie4/integrite.py` | Envoi de (C, H), vérification H = H', déchiffrement, simulation d'un attaquant |
| `partie2/` | Chiffrements César, Hill et Playfair utilisés pour obtenir C |
| `app.py` | Fenêtre CryptoLink : « Envoyer un message » (partie 2) et « Intégrité (SHA-256) » |
| `tests_partie4.py` | 11 tests et mesures de performance |

## Lancement

```
python app.py
python tests_partie4.py
```
