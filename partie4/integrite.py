"""Facade de la partie 4 (intégrité) et format du canal.

Toutes les méthodes suivent le principe de la signature numérique du cours
(3.5) : A calcule l'empreinte h = H(M) et la signe avec sa clé PRIVÉE ;
B recalcule H(M) et vérifie la signature avec la clé PUBLIQUE de A.

Format du message dans le canal :  ALGO|code_hash|message|signature
La clé privée n'apparaît jamais dans ce format.
"""

from . import elgamal, merkle_hellman, rabin, rsa
from .arithmetique import exp_mod
from .hachage import (
    ALGORITHMES, CODES_HASH, HASH_PAR_CODE, effet_avalanche, hacher, hacher_hex,
    sha256_manuel,
)

SIGNATURES = {m.NOM: m for m in (rsa, rabin, elgamal, merkle_hellman)}
CODES_SIGNATURE = {"RSA": "RSA", "Rabin": "RAB", "ElGamal": "ELG", "Merkle-Hellman": "MKH"}
SIGNATURE_PAR_CODE = {code: nom for nom, code in CODES_SIGNATURE.items()}


def generer_cles(algorithme_signature):
    return SIGNATURES[algorithme_signature].generer_cles()


def construire_message_canal(signature_algo, algorithme, message, signature):
    try:
        return "%s|%s|%s|%s" % (
            CODES_SIGNATURE[signature_algo], CODES_HASH[algorithme], message, signature,
        )
    except KeyError as error:
        raise ValueError("algorithme inconnu") from error


def lire_message_canal(message_canal):
    """Retourne (algorithme de signature, algorithme de hachage, message, signature)."""
    parts = message_canal.split("|", 2)
    if len(parts) != 3 or "|" not in parts[2]:
        raise ValueError("message du canal invalide : champs manquants")
    code_signature, code_hash, reste = parts
    message, signature = reste.rsplit("|", 1)
    try:
        return SIGNATURE_PAR_CODE[code_signature], HASH_PAR_CODE[code_hash], message, signature
    except KeyError as error:
        raise ValueError("code d'algorithme inconnu dans le canal") from error


def envoyer_signe(signature_algo, message, cle_privee, algorithme):
    """Entité A : h = H(M), S = signature de h avec la clé privée, envoi de (M, S)."""
    signature = SIGNATURES[signature_algo].signer(message, cle_privee, algorithme)
    return construire_message_canal(signature_algo, algorithme, message, signature)


def verification_automatique(message_canal, cles_publiques):
    """Entité B : lit l'algorithme dans le canal et vérifie avec la clé publique de A.

    cles_publiques : {nom de l'algorithme de signature: clé publique de A}.
    Retourne (valide, algorithme de signature, algorithme de hachage, message, h1, h2).
    """
    signature_algo, algorithme, message, signature = lire_message_canal(message_canal)
    try:
        valide, h1, h2 = SIGNATURES[signature_algo].verifier(
            message, signature, cles_publiques[signature_algo], algorithme,
        )
    except (ValueError, KeyError):
        valide, h1, h2 = False, 0, 0          # signature illisible = signature invalide
    return valide, signature_algo, algorithme, message, h1, h2


__all__ = [
    "ALGORITHMES", "SIGNATURES", "construire_message_canal", "lire_message_canal",
    "envoyer_signe", "verification_automatique", "generer_cles", "hacher", "hacher_hex",
    "sha256_manuel", "effet_avalanche", "exp_mod",
]
