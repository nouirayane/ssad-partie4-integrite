"""Signature numérique avec RSA (cours 3.3.2 et 3.5.1).

Création des clés : p, q premiers, n = p*q, phi(n) = (p-1)(q-1),
e premier avec phi(n), d = e^-1 mod phi(n).
Clé publique (e, n) ; clé privée (d, n), jamais envoyée.

Signature  : h = H(M) ; S = h^d mod n ; envoyer (M, S).
Vérification : h1 = H(M) ; h2 = S^e mod n ; valide si h1 = h2.
"""

from .arithmetique import entier, exp_mod, generer_premier, inverse_modulaire, pgcd
from .hachage import hacher

NOM = "RSA"
FORMULE = ("A : h = H(M), S = h^d mod n (clé privée d).  "
           "B : h1 = H(M), h2 = S^e mod n (clé publique e, n), valide si h1 = h2.")


def generer_cles(bits=1024, e=65537):
    while True:
        p = generer_premier(bits // 2)
        q = generer_premier(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and pgcd(e, phi) == 1:
            break
    n = p * q
    d = inverse_modulaire(e, phi)
    return {"e": e, "n": n}, {"d": d, "n": n, "p": p, "q": q}


def cles_depuis(p, q, e):
    """Clés à partir de p, q, e donnés (exemple 3 du cours)."""
    n, phi = p * q, (p - 1) * (q - 1)
    return {"e": e, "n": n}, {"d": inverse_modulaire(e, phi), "n": n, "p": p, "q": q}


def signer(message, privee, algorithme):
    h = entier(hacher(message, algorithme))
    return "%x" % exp_mod(h, privee["d"], privee["n"])


def verifier(message, signature, publique, algorithme):
    """Retourne (valide, h1, h2)."""
    n = publique["n"]
    h1 = entier(hacher(message, algorithme)) % n
    s = int(signature, 16)
    h2 = exp_mod(s, publique["e"], n)
    return h1 == h2, h1, h2


def decrire_cles(publique, privee):
    return [
        "Clé publique (e, n) : e = %d, n = %s (%d bits)"
        % (publique["e"], court(publique["n"]), publique["n"].bit_length()),
        "Clé privée (d, n) : d = %s  (gardée par A, jamais envoyée)" % court(privee["d"]),
    ]


def court(x, taille=24):
    t = "%x" % x
    return t if len(t) <= taille else "%s...%s" % (t[:taille // 2], t[-taille // 2:])
