import hashlib
import hmac as hmac_ref
import os
import time
import unittest

from partie4 import integrite
from partie4.rsa import est_premier, inverse_modulaire

SHA = "SHA-256 (implémenté)"
NOMS_HASHLIB = {"SHA-512": "sha512", "SHA3-256": "sha3_256", "SHA-1": "sha1", "MD5": "md5"}


class HachageTests(unittest.TestCase):
    def test_sha256_vecteurs_officiels(self):
        self.assertEqual(
            integrite.sha256_manuel("abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(
            integrite.sha256_manuel("").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_sha256_identique_a_hashlib(self):
        for taille in (0, 1, 55, 56, 63, 64, 65, 119, 1000):
            data = os.urandom(taille)
            self.assertEqual(integrite.sha256_manuel(data), hashlib.sha256(data).digest())

    def test_tailles_des_empreintes(self):
        for nom, (_, bits, _) in integrite.ALGORITHMES.items():
            self.assertEqual(len(integrite.hacher("x", nom)) * 8, bits)

    def test_effet_avalanche(self):
        _, h1, h2, changes, total = integrite.effet_avalanche("Bonjour", SHA)
        self.assertNotEqual(h1, h2)
        self.assertTrue(0.3 * total < changes < 0.7 * total)


class RSATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.publique, cls.privee = integrite.generer_cles(1024)

    def test_miller_rabin(self):
        self.assertTrue(est_premier(2 ** 127 - 1))
        self.assertFalse(est_premier(561))  # nombre de Carmichael

    def test_inverse_modulaire(self):
        self.assertEqual(inverse_modulaire(3, 11), 4)

    def test_cles_coherentes(self):
        e, n = self.publique
        d, _ = self.privee
        m = 123456789
        self.assertEqual(pow(pow(m, e, n), d, n), m)

    def test_signature_valide_pour_tous_les_hachages(self):
        for nom in integrite.ALGORITHMES:
            canal = integrite.envoyer_signe("Bonjour B", self.privee, nom)
            self.assertTrue(integrite.verification_automatique(canal, cle_publique_a=self.publique)[0])

    def test_message_modifie_detecte(self):
        canal = integrite.envoyer_signe("Virement de 1000 DA", self.privee, SHA)
        canal = canal.replace("1000", "9000")
        self.assertFalse(integrite.verification_automatique(canal, cle_publique_a=self.publique)[0])

    def test_signature_modifiee_detectee(self):
        canal = integrite.envoyer_signe("Bonjour", self.privee, SHA)
        canal = canal[:-1] + ("0" if canal[-1] != "0" else "1")
        self.assertFalse(integrite.verification_automatique(canal, cle_publique_a=self.publique)[0])

    def test_mauvaise_cle_publique(self):
        autre_publique, _ = integrite.generer_cles(1024)
        canal = integrite.envoyer_signe("Bonjour", self.privee, SHA)
        self.assertFalse(integrite.verification_automatique(canal, cle_publique_a=autre_publique)[0])

    def test_cle_privee_absente_du_canal(self):
        canal = integrite.envoyer_signe("Bonjour", self.privee, SHA)
        self.assertNotIn("%x" % self.privee[0], canal)


class HMACDiffieHellmanTests(unittest.TestCase):
    def test_meme_secret_des_deux_cotes(self):
        a, pub_a = integrite.generer_cles_dh()
        b, pub_b = integrite.generer_cles_dh()
        self.assertEqual(integrite.secret_partage(a, pub_b), integrite.secret_partage(b, pub_a))

    def test_hmac_identique_a_la_bibliotheque(self):
        cle = os.urandom(32)
        self.assertEqual(
            integrite.hmac(cle, "message", SHA),
            hmac_ref.new(cle, b"message", hashlib.sha256).hexdigest(),
        )
        for nom, ref in NOMS_HASHLIB.items():
            self.assertEqual(
                integrite.hmac(cle, "message", nom),
                hmac_ref.new(cle, b"message", ref).hexdigest(),
            )

    def test_echange_complet_et_attaque(self):
        a, pub_a = integrite.generer_cles_dh()
        b, pub_b = integrite.generer_cles_dh()
        canal = integrite.envoyer_hmac("Rendez-vous a midi", integrite.secret_partage(a, pub_b), SHA)
        cle_b = integrite.secret_partage(b, pub_a)
        self.assertTrue(integrite.verification_automatique(canal, cle_secrete_b=cle_b)[0])
        modifie = canal.replace("midi", "minuit")
        self.assertFalse(integrite.verification_automatique(modifie, cle_secrete_b=cle_b)[0])
        cle_attaquant = integrite.secret_partage(integrite.generer_cles_dh()[0], pub_a)
        self.assertFalse(integrite.verification_automatique(canal, cle_secrete_b=cle_attaquant)[0])


class CanalTests(unittest.TestCase):
    def test_message_avec_separateur(self):
        canal = integrite.construire_message_canal("Signature RSA", SHA, "a|b|c", "ff")
        self.assertEqual(integrite.lire_message_canal(canal), ("Signature RSA", SHA, "a|b|c", "ff"))

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            integrite.lire_message_canal("SIG|99|message|ff")
        with self.assertRaises(ValueError):
            integrite.lire_message_canal("n'importe quoi")


class PerformanceTests(unittest.TestCase):
    def test_afficher_les_performances(self):
        data = os.urandom(100_000)
        print("\nHachage de 100 Ko :")
        for nom in integrite.ALGORITHMES:
            debut = time.perf_counter()
            integrite.hacher(data, nom)
            print("  %-22s %8.2f ms" % (nom, (time.perf_counter() - debut) * 1000))
        debut = time.perf_counter()
        publique, privee = integrite.generer_cles(1024)
        print("Génération des clés RSA 1024 bits : %.0f ms" % ((time.perf_counter() - debut) * 1000))
        debut = time.perf_counter()
        canal = integrite.envoyer_signe("Bonjour", privee, SHA)
        print("Signature : %.2f ms" % ((time.perf_counter() - debut) * 1000))
        debut = time.perf_counter()
        integrite.verification_automatique(canal, cle_publique_a=publique)
        print("Vérification : %.2f ms" % ((time.perf_counter() - debut) * 1000))


if __name__ == "__main__":
    unittest.main(verbosity=2)
