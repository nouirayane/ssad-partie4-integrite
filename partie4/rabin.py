"""Signature numérique avec Rabin (cours 3.3.3 et 3.5.2).

Clés : p, q premiers avec p mod 4 = q mod 4 = 3 ; clé publique n = p*q,
clé privée (p, q), jamais envoyée.

Signature  : h = H(M) ; a = h^(1/2) mod n (racine carrée calculée avec les
étapes du déchiffrement de Rabin) ; choisir S parmi les quatre solutions.
Vérification : h1 = H(M) ; h2 = S^2 mod n ; valide si h1 = h2.

Une racine carrée n'existe que si h est un carré modulo p et modulo q.
Si ce n'est pas le cas, A ajoute un compteur U au message (H(M || U)) et
recommence ; U est envoyé avec S (ce n'est pas une donnée secrète).
"""

from .arithmetique import entier, euclide_etendu, exp_mod, generer_premier
from .hachage import hacher
from .rsa import court

NOM = "Rabin"
FORMULE = ("A : h = H(M || U), S = racine carrée de h mod n (clé privée p, q).  "
           "B : h1 = H(M || U), h2 = S^2 mod n (clé publique n), valide si h1 = h2.")


def generer_cles(bits=1024):
    condition = lambda x: x % 4 == 3
    while True:
        p = generer_premier(bits // 2, condition)
        q = generer_premier(bits // 2, condition)
        if p != q:
            return {"n": p * q}, {"p": p, "q": q}


def est_carre(h, p):
    """Critère d'Euler : h est un carré modulo p si h^((p-1)/2) = 1 mod p."""
    return h % p == 0 or exp_mod(h, (p - 1) // 2, p) == 1


def racines_carrees(c, p, q):
    """Étapes du déchiffrement de Rabin (cours 3.3.3.3) : les 4 racines de c mod n."""
    n = p * q
    mp = exp_mod(c, (p + 1) // 4, p)          # étape 1
    mq = exp_mod(c, (q + 1) // 4, q)
    _, yp, yq = euclide_etendu(p, q)           # étape 2 : p*yp + q*yq = 1
    r = (yp * p * mq + yq * q * mp) % n        # étape 3
    s = (yp * p * mq - yq * q * mp) % n
    return [r, n - r, s, n - s]


def h_avec_compteur(message, u, algorithme):
    data = message.encode("utf-8") + b"||" + str(u).encode()
    return entier(hacher(data, algorithme))


def signer(message, privee, algorithme):
    p, q = privee["p"], privee["q"]
    u = 0
    while True:
        h = h_avec_compteur(message, u, algorithme) % (p * q)
        if est_carre(h, p) and est_carre(h, q):
            break
        u += 1
    s = min(racines_carrees(h, p, q))           # choisir S parmi les 4 solutions
    return "%d:%x" % (u, s)


def verifier(message, signature, publique, algorithme):
    n = publique["n"]
    u, s = signature.split(":")
    h1 = h_avec_compteur(message, int(u), algorithme) % n
    h2 = exp_mod(int(s, 16), 2, n)
    return h1 == h2, h1, h2


def decrire_cles(publique, privee):
    return [
        "Clé publique : n = %s (%d bits)" % (court(publique["n"]), publique["n"].bit_length()),
        "Clé privée (p, q) : p = %s, q = %s  (p, q = 3 mod 4, jamais envoyés)"
        % (court(privee["p"], 16), court(privee["q"], 16)),
    ]
