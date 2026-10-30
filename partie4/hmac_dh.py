"""HMAC (RFC 2104) implémenté à la main, avec une clé obtenue par
l'échange de Diffie-Hellman.

Chaque entité possède une clé PRIVÉE (exposant secret a ou b) et une clé
PUBLIQUE (g^a mod p ou g^b mod p). Seules les clés publiques passent dans
le canal ; A et B calculent chacun la même clé secrète g^(ab) mod p, qui
n'est donc jamais transmise.
"""

import secrets

from .hachage import ALGORITHMES, hacher

# Groupe MODP de 2048 bits (RFC 3526, groupe 14), générateur g = 2.
P_DH = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G_DH = 2

# Taille de bloc interne (en octets) de chaque fonction de hachage, utilisée par HMAC.
TAILLE_BLOC = {
    "SHA-256 (implémenté)": 64,
    "SHA-512": 128,
    "SHA3-256": 136,
    "SHA-1": 64,
    "MD5": 64,
}


def generer_cles_dh():
    """Retourne (cle_privee, cle_publique) pour une entité."""
    privee = secrets.randbelow(P_DH - 3) + 2
    return privee, pow(G_DH, privee, P_DH)


def secret_partage(ma_cle_privee, cle_publique_autre):
    """Calcule g^(ab) mod p puis en dérive une clé HMAC de 32 octets."""
    if not 1 < cle_publique_autre < P_DH - 1:
        raise ValueError("clé publique Diffie-Hellman invalide")
    s = pow(cle_publique_autre, ma_cle_privee, P_DH)
    return hacher(s.to_bytes(256, "big"), "SHA-256 (implémenté)")


def hmac(cle, message, algorithme="SHA-256 (implémenté)"):
    """HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))."""
    if algorithme not in ALGORITHMES:
        raise ValueError("algorithme de hachage inconnu")
    if isinstance(message, str):
        message = message.encode("utf-8")
    bloc = TAILLE_BLOC[algorithme]
    if len(cle) > bloc:
        cle = hacher(cle, algorithme)
    cle = cle.ljust(bloc, b"\x00")
    ipad = bytes(x ^ 0x36 for x in cle)
    opad = bytes(x ^ 0x5C for x in cle)
    interne = hacher(ipad + message, algorithme)
    return hacher(opad + interne, algorithme).hex()


def verifier_hmac(cle, message, tag_hex, algorithme="SHA-256 (implémenté)"):
    attendu = hmac(cle, message, algorithme)
    return secrets.compare_digest(attendu, tag_hex.strip().lower()), attendu
