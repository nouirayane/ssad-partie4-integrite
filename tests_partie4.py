import hashlib
import os
import time
import unittest

from partie4 import integrite

MESSAGE = "Retrouve-moi a la bibliotheque a midi"


def envoyer(algorithme, message=MESSAGE, sens="droite"):
    chiffrement = integrite.Chiffrement()
    c, h = integrite.envoyer(chiffrement, algorithme, message,
                             integrite.CLES_PAR_DEFAUT[algorithme], sens)
    return chiffrement, c, h


class SHA256Tests(unittest.TestCase):
    def test_vecteurs_officiels(self):
        self.assertEqual(
            integrite.sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(
            integrite.sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_identique_a_hashlib(self):
        for taille in (0, 1, 55, 56, 63, 64, 65, 119, 1000):
            data = os.urandom(taille)
            self.assertEqual(integrite.sha256_manuel(data), hashlib.sha256(data).digest())

    def test_taille_fixe(self):
        for texte in ("a", MESSAGE, "x" * 5000):
            self.assertEqual(len(integrite.sha256_hex(texte)), 64)


class IntegriteTests(unittest.TestCase):
    def test_hash_calcule_sur_le_chiffre(self):
        _, c, h = envoyer("Caesar")
        self.assertEqual(h, integrite.sha256_hex(c))
        self.assertNotEqual(h, integrite.sha256_hex(MESSAGE))

    def test_message_intact_dechiffre(self):
        for algorithme in integrite.ALGORITHMES:
            for sens in ("droite", "gauche"):
                chiffrement, c, h = envoyer(algorithme, sens=sens)
                ok, h_calcule, clair = integrite.recevoir(
                    chiffrement, c, h, integrite.CLES_PAR_DEFAUT[algorithme]
                )
                self.assertTrue(ok)
                self.assertEqual(h_calcule, h)
                self.assertEqual(clair.upper(), MESSAGE.upper())

    def test_cesar_garde_la_casse(self):
        chiffrement, c, h = envoyer("Caesar")
        self.assertEqual(integrite.recevoir(chiffrement, c, h, "3")[2], MESSAGE)

    def test_modification_detectee_et_dechiffrement_bloque(self):
        for algorithme in integrite.ALGORITHMES:
            chiffrement, c, h = envoyer(algorithme)
            modifie, numero, ancienne, nouvelle = integrite.falsifier(c)
            self.assertEqual(numero, 1)
            self.assertNotEqual(ancienne, nouvelle)
            ok, h_calcule, clair = integrite.recevoir(
                chiffrement, modifie, h, integrite.CLES_PAR_DEFAUT[algorithme]
            )
            self.assertFalse(ok)
            self.assertNotEqual(h_calcule, h)
            self.assertIsNone(clair)

    def test_falsifier_change_un_seul_caractere(self):
        _, c, _ = envoyer("Caesar")
        modifie = integrite.falsifier(c)[0]
        self.assertEqual(len(modifie), len(c))
        self.assertEqual(sum(a != b for a, b in zip(c, modifie)), 1)
        self.assertEqual(integrite.falsifier("000:r:Zebre")[0], "000:r:Aebre")

    def test_hash_modifie_detecte(self):
        chiffrement, c, h = envoyer("Hill")
        faux = ("0" if h[0] != "0" else "1") + h[1:]
        self.assertFalse(integrite.verifier(c, faux)[0])

    def test_cle_absente_du_canal(self):
        _, c, h = envoyer("Playfair")
        self.assertNotIn("monarchy", (c + h).lower())


class PerformanceTests(unittest.TestCase):
    def test_afficher_les_performances(self):
        print("\nSHA-256 implémenté à la main :")
        for taille in (100, 10_000, 100_000):
            data = os.urandom(taille)
            debut = time.perf_counter()
            integrite.sha256_manuel(data)
            manuel = (time.perf_counter() - debut) * 1000
            debut = time.perf_counter()
            hashlib.sha256(data).digest()
            biblio = (time.perf_counter() - debut) * 1000
            print("  %7d octets : %8.2f ms  (hashlib : %.3f ms)" % (taille, manuel, biblio))
        for algorithme in integrite.ALGORITHMES:
            debut = time.perf_counter()
            chiffrement, c, h = envoyer(algorithme)
            integrite.recevoir(chiffrement, c, h, integrite.CLES_PAR_DEFAUT[algorithme])
            print("  %-8s chiffrer + hacher + vérifier + déchiffrer : %.2f ms"
                  % (algorithme, (time.perf_counter() - debut) * 1000))


if __name__ == "__main__":
    unittest.main(verbosity=2)
