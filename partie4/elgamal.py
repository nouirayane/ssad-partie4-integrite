"""Signature numérique avec ElGamal (cours 3.3.5 et 3.5.4).

Clés : p premier, g < p, a < p secret ; A = g^a mod p.
Clé publique (A, g, p) ; clé privée a, jamais envoyée.

Signature  : h = H(M) ; choisir b aléatoire avec pgcd(b, p-1) = 1 ;
             B = g^b mod p ; C tel que h = (a*B + b*C) mod (p-1) ; S = (B, C).
Vérification : valide si A^B * B^C mod p = g^h mod p.
"""

import secrets

from .arithmetique import entier, exp_mod, generer_premier, inverse_modulaire, pgcd
from .hachage import hacher
from .rsa import court

NOM = "ElGamal"
FORMULE = ("A : h = H(M), B = g^b mod p, C = (h - a*B) * b^-1 mod (p-1) (clé privée a).  "
           "B : valide si A^B * B^C mod p = g^h mod p (clé publique A, g, p).")


def generer_cles(bits=512):
    p = generer_premier(bits)
    g = secrets.randbelow(p - 3) + 2
    a = secrets.randbelow(p - 3) + 2
    return cles_depuis(p, g, a)


def cles_depuis(p, g, a):
    """Clés à partir de valeurs données (exemple 7 du cours)."""
    return {"A": exp_mod(g, a, p), "g": g, "p": p}, {"a": a, "g": g, "p": p}


def signer(message, privee, algorithme, b=None):
    p, a, g = privee["p"], privee["a"], privee["g"]
    h = entier(hacher(message, algorithme))
    while b is None or pgcd(b, p - 1) != 1:
        b = secrets.randbelow(p - 3) + 2
    grand_b = exp_mod(g, b, p)
    c = (h - a * grand_b) * inverse_modulaire(b, p - 1) % (p - 1)
    return "%x:%x" % (grand_b, c)


def verifier(message, signature, publique, algorithme):
    """h1 = A^B * B^C mod p ; h2 = g^h mod p."""
    grand_a, g, p = publique["A"], publique["g"], publique["p"]
    grand_b, c = (int(x, 16) for x in signature.split(":"))
    if not 0 < grand_b < p:
        return False, 0, 0
    h = entier(hacher(message, algorithme))
    h1 = exp_mod(grand_a, grand_b, p) * exp_mod(grand_b, c, p) % p
    h2 = exp_mod(g, h, p)
    return h1 == h2, h1, h2


def decrire_cles(publique, privee):
    return [
        "Clé publique (A, g, p) : A = %s, g = %s, p = %s (%d bits)"
        % (court(publique["A"], 16), court(publique["g"], 16), court(publique["p"], 16),
           publique["p"].bit_length()),
        "Clé privée : a = %s  (gardée par A, jamais envoyée)" % court(privee["a"]),
    ]
