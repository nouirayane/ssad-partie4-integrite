"""RSA implémenté à la main : génération des clés publique/privée,
signature numérique d'une empreinte et vérification.

Principe :  A signe avec sa clé PRIVÉE (d, n), B vérifie avec la clé
PUBLIQUE de A (e, n). La clé privée ne quitte jamais l'entité A : elle
n'est jamais placée dans le canal.
"""

import secrets

from .hachage import CODES_HASH, hacher

PETITS_PREMIERS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
E_PUBLIC = 65537


def est_premier(n, tours=40):
    """Test probabiliste de Miller-Rabin (erreur < 4^-tours)."""
    if n < 2:
        return False
    for p in PETITS_PREMIERS:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(tours):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generer_premier(bits):
    while True:
        # bit de poids fort à 1 (taille exacte) et bit de poids faible à 1 (impair)
        candidat = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if est_premier(candidat):
            return candidat


def pgcd(a, b):
    while b:
        a, b = b, a % b
    return a


def inverse_modulaire(a, m):
    """Algorithme d'Euclide étendu : retourne x tel que a*x = 1 mod m."""
    ancien_r, r = a, m
    ancien_s, s = 1, 0
    while r:
        q = ancien_r // r
        ancien_r, r = r, ancien_r - q * r
        ancien_s, s = s, ancien_s - q * s
    if ancien_r != 1:
        raise ValueError("pas d'inverse modulaire")
    return ancien_s % m


def generer_cles(bits=1024):
    """Retourne (cle_publique, cle_privee) avec cle = (exposant, n)."""
    if bits < 512:
        raise ValueError("la taille de clé doit être d'au moins 512 bits")
    while True:
        p = generer_premier(bits // 2)
        q = generer_premier(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if pgcd(E_PUBLIC, phi) == 1:
            break
    n = p * q
    d = inverse_modulaire(E_PUBLIC, phi)
    return (E_PUBLIC, n), (d, n)


def taille_octets(n):
    return (n.bit_length() + 7) // 8


def bourrage(empreinte, algorithme, k):
    """Bourrage inspiré de PKCS#1 v1.5 : 00 01 FF..FF 00 | code hash | empreinte.

    Sans bourrage, le RSA « manuel » est malléable (signature de s1*s2 =
    signature de m1*m2) ; le bourrage fixe la structure du bloc signé.
    """
    corps = bytes.fromhex(CODES_HASH[algorithme]) + empreinte
    nb_ff = k - len(corps) - 3
    if nb_ff < 8:
        raise ValueError("clé RSA trop petite pour cette fonction de hachage")
    return b"\x00\x01" + b"\xff" * nb_ff + b"\x00" + corps


def signer(message, cle_privee, algorithme="SHA-256 (implémenté)"):
    """Signature = (bourrage(H(message)))^d mod n, en hexadécimal."""
    d, n = cle_privee
    k = taille_octets(n)
    bloc = bourrage(hacher(message, algorithme), algorithme, k)
    signature = pow(int.from_bytes(bloc, "big"), d, n)
    return signature.to_bytes(k, "big").hex()


def empreinte_signee(signature_hex, cle_publique):
    """Retrouve l'empreinte contenue dans la signature : s^e mod n."""
    e, n = cle_publique
    k = taille_octets(n)
    s = int(signature_hex, 16)
    if s >= n:
        raise ValueError("signature invalide")
    return pow(s, e, n).to_bytes(k, "big")


def verifier(message, signature_hex, cle_publique, algorithme="SHA-256 (implémenté)"):
    """Retourne (valide, empreinte recalculée, bloc déchiffré de la signature)."""
    e, n = cle_publique
    attendu = bourrage(hacher(message, algorithme), algorithme, taille_octets(n))
    try:
        obtenu = empreinte_signee(signature_hex, cle_publique)
    except ValueError:
        return False, attendu, b""
    return secrets.compare_digest(attendu, obtenu), attendu, obtenu
