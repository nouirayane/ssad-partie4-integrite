"""Outils arithmétiques communs aux signatures (cours, chapitre 3).

Toutes les puissances modulaires du projet passent par exp_mod, qui suit
l'algorithme 1 du cours (CExpMod, exponentiation modulaire rapide).
"""

import secrets


def exp_mod(p, j, n):
    """CExpMod(P, J, N) du cours : calcule P^J mod N avec R = 1.

    tant que J > 0 :
        si J est impair : R <- R * P mod N
        P <- P^2 mod N ;  J <- J div 2
    Nombre de multiplications : au plus 2 * log2(J).
    """
    if n == 1:
        return 0
    r = 1
    p %= n
    while j > 0:
        if j % 2 == 1:
            r = r * p % n
        p = p * p % n
        j //= 2
    return r


def pgcd(a, b):
    while b:
        a, b = b, a % b
    return a


def euclide_etendu(a, b):
    """Retourne (g, x, y) tel que a*x + b*y = g = pgcd(a, b)."""
    ancien_r, r = a, b
    ancien_x, x = 1, 0
    ancien_y, y = 0, 1
    while r:
        q = ancien_r // r
        ancien_r, r = r, ancien_r - q * r
        ancien_x, x = x, ancien_x - q * x
        ancien_y, y = y, ancien_y - q * y
    return ancien_r, ancien_x, ancien_y


def inverse_modulaire(a, m):
    """x tel que a*x = 1 mod m (algorithme d'Euclide étendu)."""
    g, x, _ = euclide_etendu(a % m, m)
    if g != 1:
        raise ValueError("%d n'est pas inversible modulo %d" % (a, m))
    return x % m


PETITS_PREMIERS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]


def est_premier(n, tours=20):
    """Test de Miller-Rabin, calculé avec exp_mod."""
    if n < 2:
        return False
    for p in PETITS_PREMIERS:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(tours):
        x = exp_mod(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generer_premier(bits, condition=lambda p: True):
    """Grand nombre premier de `bits` bits vérifiant `condition`."""
    while True:
        candidat = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if condition(candidat) and est_premier(candidat):
            return candidat


def entier(empreinte):
    """Convertit une empreinte (bytes) en entier h."""
    return int.from_bytes(empreinte, "big")
