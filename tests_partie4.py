import hashlib
import os
import time
import unittest

from partie4 import elgamal, integrite, merkle_hellman, rabin, rsa
from partie4.arithmetique import est_premier, exp_mod, inverse_modulaire

SHA = "SHA-256 (implémenté)"


class ExemplesDuCoursTests(unittest.TestCase):
    """Valeurs reprises des exemples du chapitre 3 du cours."""

    def test_exponentiation_rapide(self):
        # 3.2.3 : C = 150^233 mod 437 = 351
        self.assertEqual(exp_mod(150, 233, 437), 351)
        for _ in range(50):
            a, j, n = (int.from_bytes(os.urandom(16), "big") for _ in range(3))
            self.assertEqual(exp_mod(a, j, n + 2), pow(a, j, n + 2))

    def test_rsa_exemple_3(self):
        # p = 47, q = 59, e = 17 -> n = 2773, d = 157 ; B (66) -> 872 -> 66
        publique, privee = rsa.cles_depuis(47, 59, 17)
        self.assertEqual((publique["n"], privee["d"]), (2773, 157))
        self.assertEqual(exp_mod(66, 17, 2773), 872)
        self.assertEqual(exp_mod(872, 157, 2773), 66)

    def test_rabin_exemple_4(self):
        # p = 11, q = 23, M = 158 -> C = 170 ; solutions 26, 95, 227, 158
        self.assertEqual(exp_mod(158, 2, 253), 170)
        self.assertEqual(sorted(rabin.racines_carrees(170, 11, 23)), [26, 95, 158, 227])

    def test_merkle_hellman_exemples_5_et_6(self):
        # Exemple 5 : A = (2, 3, 6, 13, 27, 52), T = 70 -> b = 1 1 0 1 0 1
        suite = [2, 3, 6, 13, 27, 52]
        self.assertEqual(merkle_hellman.resoudre_super_croissante(70, suite), [1, 1, 0, 1, 0, 1])
        # Exemple 6 : n = 31, m = 105 -> B = (62, 93, 81, 88, 102, 37)
        publique, _ = merkle_hellman.cles_depuis(suite, 31, 105)
        self.assertEqual(publique["B"], [62, 93, 81, 88, 102, 37])
        self.assertEqual(inverse_modulaire(31, 105), 61)

    def test_elgamal_exemple_7(self):
        # p = 23, g = 7, a = 6 -> A = 4
        publique, _ = elgamal.cles_depuis(23, 7, 6)
        self.assertEqual(publique["A"], 4)

    def test_elgamal_signature_petits_nombres(self):
        publique, privee = elgamal.cles_depuis(23, 7, 6)
        canal = elgamal.signer("Bonjour", privee, SHA, b=3)
        self.assertTrue(elgamal.verifier("Bonjour", canal, publique, SHA)[0])


class HachageTests(unittest.TestCase):
    def test_sha256_vecteurs_officiels(self):
        self.assertEqual(
            integrite.sha256_manuel("abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_sha256_identique_a_hashlib(self):
        for taille in (0, 1, 55, 56, 63, 64, 65, 1000):
            data = os.urandom(taille)
            self.assertEqual(integrite.sha256_manuel(data), hashlib.sha256(data).digest())

    def test_compression_taille_fixe(self):
        for nom, (_, bits, _) in integrite.ALGORITHMES.items():
            self.assertEqual(len(integrite.hacher("x" * 5000, nom)) * 8, bits)

    def test_effet_avalanche(self):
        _, h1, h2, changes, total = integrite.effet_avalanche("Bonjour", SHA)
        self.assertTrue(0.3 * total < changes < 0.7 * total)


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cles = {nom: integrite.generer_cles(nom) for nom in integrite.SIGNATURES}
        cls.publiques = {nom: cles[0] for nom, cles in cls.cles.items()}

    def envoyer(self, nom, message, algorithme=SHA):
        return integrite.envoyer_signe(nom, message, self.cles[nom][1], algorithme)

    def test_signature_valide(self):
        for nom in integrite.SIGNATURES:
            for algorithme in integrite.ALGORITHMES:
                canal = self.envoyer(nom, "Bonjour B", algorithme)
                valide = integrite.verification_automatique(canal, self.publiques)[0]
                self.assertTrue(valide, (nom, algorithme))

    def test_message_modifie_detecte(self):
        for nom in integrite.SIGNATURES:
            canal = self.envoyer(nom, "Virement de 1000 DA").replace("1000", "9000")
            self.assertFalse(integrite.verification_automatique(canal, self.publiques)[0], nom)

    def test_signature_modifiee_detectee(self):
        for nom in integrite.SIGNATURES:
            canal = self.envoyer(nom, "Bonjour")
            canal = canal[:-1] + ("0" if canal[-1] != "0" else "1")
            self.assertFalse(integrite.verification_automatique(canal, self.publiques)[0], nom)

    def test_mauvaise_cle_publique(self):
        for nom in integrite.SIGNATURES:
            canal = self.envoyer(nom, "Bonjour")
            autres = dict(self.publiques, **{nom: integrite.generer_cles(nom)[0]})
            self.assertFalse(integrite.verification_automatique(canal, autres)[0], nom)

    def test_cle_privee_absente_du_canal(self):
        privees = {
            "RSA": self.cles["RSA"][1]["d"], "Rabin": self.cles["Rabin"][1]["p"],
            "ElGamal": self.cles["ElGamal"][1]["a"], "Merkle-Hellman": self.cles["Merkle-Hellman"][1]["n"],
        }
        for nom, secret in privees.items():
            canal = self.envoyer(nom, "Bonjour")
            self.assertNotIn("%x" % secret, canal, nom)
            self.assertNotIn(str(secret), canal, nom)

    def test_signature_illisible(self):
        canal = integrite.construire_message_canal("RSA", SHA, "Bonjour", "zz")
        self.assertFalse(integrite.verification_automatique(canal, self.publiques)[0])


class CanalTests(unittest.TestCase):
    def test_message_avec_separateur(self):
        canal = integrite.construire_message_canal("ElGamal", SHA, "a|b|c", "ff:01")
        self.assertEqual(integrite.lire_message_canal(canal), ("ElGamal", SHA, "a|b|c", "ff:01"))

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            integrite.lire_message_canal("XXX|01|message|ff")
        with self.assertRaises(ValueError):
            integrite.lire_message_canal("n'importe quoi")


class PerformanceTests(unittest.TestCase):
    def test_afficher_les_performances(self):
        print("\n%-16s %12s %12s %14s" % ("Signature", "Clés (ms)", "Signer (ms)", "Vérifier (ms)"))
        for nom in integrite.SIGNATURES:
            debut = time.perf_counter()
            publique, privee = integrite.generer_cles(nom)
            t_cles = time.perf_counter() - debut
            debut = time.perf_counter()
            canal = integrite.envoyer_signe(nom, "Bonjour", privee, SHA)
            t_signer = time.perf_counter() - debut
            debut = time.perf_counter()
            integrite.verification_automatique(canal, {nom: publique})
            t_verifier = time.perf_counter() - debut
            print("%-16s %12.1f %12.2f %14.2f" % (nom, t_cles * 1000, t_signer * 1000, t_verifier * 1000))
        data = os.urandom(100_000)
        print("Hachage de 100 Ko :")
        for nom in integrite.ALGORITHMES:
            debut = time.perf_counter()
            integrite.hacher(data, nom)
            print("  %-22s %8.2f ms" % (nom, (time.perf_counter() - debut) * 1000))


if __name__ == "__main__":
    unittest.main(verbosity=2)
