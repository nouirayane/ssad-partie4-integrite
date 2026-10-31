# SSAD TP1 - Partie 4 : Intégrité

Réalisation de l'objectif **intégrité** en suivant le chapitre 3 du cours
(fonction de hachage et signature numérique). Python 3, bibliothèque standard uniquement.

## Principe

A calcule l'empreinte `h = H(M)` et la signe avec sa **clé privée** ; B recalcule
l'empreinte et vérifie la signature avec la **clé publique** de A. La clé privée n'est
jamais envoyée dans le canal. Si le message ou la signature est modifié, `h1 ≠ h2`.

## Contenu

| Fichier | Rôle |
|---------|------|
| `partie4/arithmetique.py` | Exponentiation modulaire rapide (CExpMod), Euclide étendu, nombres premiers |
| `partie4/hachage.py` | SHA-256 écrit à la main + MD5, SHA-1, SHA-512, SHA3-256 |
| `partie4/rsa.py` | Signature RSA (cours 3.5.1) |
| `partie4/rabin.py` | Signature de Rabin (cours 3.5.2) |
| `partie4/merkle_hellman.py` | Signature de Merkle-Hellman (cours 3.5.3), cassé par Shamir : usage pédagogique |
| `partie4/elgamal.py` | Signature d'ElGamal (cours 3.5.4) |
| `partie4/integrite.py` | Format du canal, envoi signé, vérification automatique |
| `app.py` | Interface Tkinter : onglets Intégrité et Hachage |
| `tests_partie4.py` | 19 tests (dont les exemples du cours) et mesures de performance |

## Lancement

```
python app.py
python tests_partie4.py
```

Format du canal : `ALGO|code_hash|message|signature` avec `ALGO` = `RSA`, `RAB`, `MKH` ou `ELG`.
