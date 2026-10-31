"""Signature numérique avec Merkle-Hellman (cours 3.3.4 et 3.5.3).

Clés : suite super-croissante A = (P1..Pk), m > somme des Pi,
n avec pgcd(n, m) = 1, B = (P'1..P'k) avec P'i = n*Pi mod m.
Clé publique B ; clé privée (A, n), jamais envoyée.
Pour que B puisse comparer h2 à h1, le module m est aussi publié.

Signature  : h = H(M) ; T = n^-1 * h mod m ; calculer les bi avec
             l'algorithme 2 (suite super-croissante) ; S = b1 b2 ... bk.
Vérification : h1 = H(M) ; h2 = b1*P'1 + ... + bk*P'k mod m ; valide si h1 = h2.

T n'est pas toujours décomposable dans la suite A : dans ce cas A ajoute un
compteur U au message (H(M || U)) et recommence ; U est envoyé avec S.

Attention (cours p.44) : Merkle-Hellman a été cassé par Adi Shamir ; il est
réalisé ici pour l'étude, pas pour un usage réel.
"""

import secrets

from .arithmetique import entier, inverse_modulaire, pgcd
from .hachage import hacher
from .rsa import court

NOM = "Merkle-Hellman"
FORMULE = ("A : h = H(M || U), T = n^-1 * h mod m, bi par la suite super-croissante (clé privée A, n).  "
           "B : h2 = somme bi * P'i mod m (clé publique B, m), valide si h1 = h2.")
K = 512  # nombre d'éléments : suffisant pour une empreinte de 512 bits


def generer_cles(k=K):
    # P1 >= 2 : avec P1 = 1, P'1 = n mod m publierait directement n.
    suite, total = [secrets.randbelow(8) + 2], 0
    total = suite[0]
    for _ in range(k - 1):
        element = total + secrets.randbelow(3) + 1   # strictement > somme des précédents
        suite.append(element)
        total += element
    m = total + secrets.randbelow(total // 4) + 1       # m > somme des Pi
    while True:
        n = secrets.randbelow(m - 2) + 2
        if pgcd(n, m) == 1:
            break
    return cles_depuis(suite, n, m)


def cles_depuis(suite, n, m):
    """Clés à partir de valeurs données (exemple 6 du cours)."""
    publique = [n * p % m for p in suite]
    return {"B": publique, "m": m}, {"A": suite, "n": n, "m": m}


def resoudre_super_croissante(t, suite):
    """Algorithme 2 du cours. Retourne les bits b1..bk, ou None si pas de solution."""
    bits = [0] * len(suite)
    for i in range(len(suite) - 1, -1, -1):
        if t >= suite[i]:
            t -= suite[i]
            bits[i] = 1
    return bits if t == 0 else None


def h_avec_compteur(message, u, algorithme):
    data = message.encode("utf-8") + b"||" + str(u).encode()
    return entier(hacher(data, algorithme))


def signer(message, privee, algorithme):
    m = privee["m"]
    n_inverse = inverse_modulaire(privee["n"], m)
    u = 0
    while True:
        t = n_inverse * (h_avec_compteur(message, u, algorithme) % m) % m
        bits = resoudre_super_croissante(t, privee["A"])
        if bits is not None:
            break
        u += 1
    return "%d:%x" % (u, int("".join(map(str, reversed(bits))), 2))


def verifier(message, signature, publique, algorithme):
    suite, m = publique["B"], publique["m"]
    u, s = signature.split(":")
    valeur = int(s, 16)
    if valeur >> len(suite):
        return False, 0, 0
    bits = [(valeur >> i) & 1 for i in range(len(suite))]
    h1 = h_avec_compteur(message, int(u), algorithme) % m
    h2 = sum(b * p for b, p in zip(bits, suite)) % m
    return h1 == h2, h1, h2


def decrire_cles(publique, privee):
    b, a = publique["B"], privee["A"]
    return [
        "Clé publique : B = (%s, %s, ...) (%d éléments), m = %s"
        % (court(b[0], 12), court(b[1], 12), len(b), court(publique["m"], 16)),
        "Clé privée : A = (%d, %d, %d, ...) super-croissante, n = %s (jamais envoyée)"
        % (a[0], a[1], a[2], court(privee["n"], 16)),
    ]
