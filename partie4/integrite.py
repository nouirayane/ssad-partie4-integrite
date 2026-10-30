"""Facade de la partie 4 (authenticité / intégrité) et format du canal.

Format du message dans le canal :  MODE|code_hash|message|preuve
  - MODE = SIG : preuve = signature RSA (hexadécimal)
  - MODE = MAC : preuve = HMAC calculé avec la clé Diffie-Hellman
Aucune clé privée ni clé secrète n'apparaît dans ce format.
"""

from .hachage import (
    ALGORITHMES, CODES_HASH, HASH_PAR_CODE, effet_avalanche, hacher, hacher_hex,
    sha256_manuel,
)
from .hmac_dh import generer_cles_dh, hmac, secret_partage, verifier_hmac
from .rsa import generer_cles, signer, verifier

MODES = {"Signature RSA": "SIG", "HMAC + Diffie-Hellman": "MAC"}
MODE_PAR_CODE = {code: name for name, code in MODES.items()}


def construire_message_canal(mode, algorithme, message, preuve):
    try:
        return "%s|%s|%s|%s" % (MODES[mode], CODES_HASH[algorithme], message, preuve)
    except KeyError as error:
        raise ValueError("mode ou algorithme inconnu") from error


def lire_message_canal(message_canal):
    """Retourne (mode, algorithme, message, preuve)."""
    parts = message_canal.split("|", 2)
    if len(parts) != 3 or "|" not in parts[2]:
        raise ValueError("message du canal invalide : champs manquants")
    code_mode, code_hash, reste = parts
    message, preuve = reste.rsplit("|", 1)
    try:
        return MODE_PAR_CODE[code_mode], HASH_PAR_CODE[code_hash], message, preuve
    except KeyError as error:
        raise ValueError("mode ou code de hachage inconnu dans le canal") from error


def envoyer_signe(message, cle_privee_a, algorithme):
    signature = signer(message, cle_privee_a, algorithme)
    return construire_message_canal("Signature RSA", algorithme, message, signature)


def envoyer_hmac(message, cle_secrete, algorithme):
    tag = hmac(cle_secrete, message, algorithme)
    return construire_message_canal("HMAC + Diffie-Hellman", algorithme, message, tag)


def verification_automatique(message_canal, cle_publique_a=None, cle_secrete_b=None):
    """B lit le mode et l'algorithme dans le canal puis vérifie la preuve.

    Retourne (valide, mode, algorithme, message, empreinte attendue, empreinte reçue).
    """
    mode, algorithme, message, preuve = lire_message_canal(message_canal)
    if mode == "Signature RSA":
        if cle_publique_a is None:
            raise ValueError("la clé publique de A est requise")
        valide, attendu, obtenu = verifier(message, preuve, cle_publique_a, algorithme)
        return valide, mode, algorithme, message, attendu.hex(), obtenu.hex()
    if cle_secrete_b is None:
        raise ValueError("la clé secrète Diffie-Hellman de B est requise")
    valide, attendu = verifier_hmac(cle_secrete_b, message, preuve, algorithme)
    return valide, mode, algorithme, message, attendu, preuve


__all__ = [
    "ALGORITHMES", "MODES", "construire_message_canal", "lire_message_canal",
    "envoyer_signe", "envoyer_hmac", "verification_automatique", "generer_cles",
    "generer_cles_dh", "secret_partage", "hacher", "hacher_hex", "sha256_manuel",
    "effet_avalanche", "hmac", "signer", "verifier",
]
