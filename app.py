import tkinter as tk
from tkinter import ttk, messagebox

import hashlib
import time

from partie4 import integrite


def make_text_box(parent, height):
    box = tk.Text(parent, height=height, wrap="word")
    box.pack(fill="both", expand=True)
    return box


def set_text(box, text):
    box.config(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", text)
    box.config(state="disabled")


def get_text(box):
    return box.get("1.0", "end").strip()


def short(value, size=48):
    text = "%x" % value if isinstance(value, int) else value
    return text if len(text) <= size else "%s...%s" % (text[:size // 2], text[-size // 2:])


class IntegrityTab(ttk.Frame):
    """Partie 4 : A envoie un message accompagné d'une preuve d'intégrité
    (signature RSA ou HMAC), B la vérifie. Le canal est modifiable pour
    simuler un attaquant."""

    def __init__(self, parent):
        super().__init__(parent, padding=10)
        self.build_settings()
        self.build_keys()
        self.build_entity_a()
        self.build_channel()
        self.build_entity_b()
        self.generate_keys()

    def build_settings(self):
        settings = ttk.Frame(self)
        settings.pack(fill="x")
        ttk.Label(settings, text="Mode").grid(row=0, column=0)
        self.mode = ttk.Combobox(
            settings, values=list(integrite.MODES), state="readonly", width=22,
        )
        self.mode.current(0)
        self.mode.grid(row=0, column=1, padx=6)
        self.mode.bind("<<ComboboxSelected>>", self.change_mode)
        ttk.Label(settings, text="Fonction de hachage").grid(row=0, column=2)
        self.algorithm = ttk.Combobox(
            settings, values=list(integrite.ALGORITHMES), state="readonly", width=20,
        )
        self.algorithm.current(0)
        self.algorithm.grid(row=0, column=3, padx=6)
        ttk.Button(settings, text="Générer de nouvelles clés", command=self.generate_keys).grid(
            row=0, column=4, padx=6
        )
        self.hint = ttk.Label(self, foreground="#555", wraplength=780)
        self.hint.pack(anchor="w", pady=6)

    def build_keys(self):
        frame = ttk.LabelFrame(self, text="Clés (publiques affichées, privées jamais envoyées)", padding=6)
        frame.pack(fill="both", expand=True, pady=4)
        self.keys_box = make_text_box(frame, 4)
        self.keys_box.config(state="disabled")

    def build_entity_a(self):
        frame = ttk.LabelFrame(self, text="Entité A", padding=6)
        frame.pack(fill="both", expand=True, pady=4)
        self.message = make_text_box(frame, 2)
        self.message.insert("1.0", "Virement de 1000 DA vers le compte 0042")
        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=4)
        self.digest_a = ttk.Label(bottom, text="Empreinte H(m) : -", foreground="#555")
        self.digest_a.pack(side="left")
        ttk.Button(bottom, text="Hacher, signer et envoyer", command=self.send).pack(side="right")

    def build_channel(self):
        channel = ttk.LabelFrame(self, text="Canal (modifiable : simule un attaquant)", padding=6)
        channel.pack(fill="both", expand=True, pady=4)
        self.channel_info = ttk.Label(channel, text="Aucun message envoyé.", foreground="#555")
        self.channel_info.pack(anchor="w", pady=(0, 4))
        self.channel_box = make_text_box(channel, 3)
        buttons = ttk.Frame(channel)
        buttons.pack(fill="x", pady=4)
        ttk.Button(buttons, text="Attaquant : modifier le message", command=self.tamper_message).pack(
            side="left"
        )
        ttk.Button(buttons, text="Attaquant : falsifier la preuve", command=self.tamper_proof).pack(
            side="left", padx=6
        )

    def build_entity_b(self):
        frame = ttk.LabelFrame(self, text="Entité B", padding=6)
        frame.pack(fill="both", expand=True, pady=4)
        self.result_box = make_text_box(frame, 4)
        self.result_box.config(state="disabled")
        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=4)
        self.status = ttk.Label(bottom, font=("TkDefaultFont", 10, "bold"))
        self.status.pack(side="left")
        ttk.Button(bottom, text="Vérifier l'intégrité", command=self.receive).pack(side="right")

    def generate_keys(self):
        start = time.perf_counter()
        self.rsa_public, self.rsa_private = integrite.generer_cles(1024)
        self.dh_private_a, self.dh_public_a = integrite.generer_cles_dh()
        self.dh_private_b, self.dh_public_b = integrite.generer_cles_dh()
        self.key_time = (time.perf_counter() - start) * 1000
        self.change_mode()

    def change_mode(self, event=None):
        if self.mode.get() == "Signature RSA":
            e, n = self.rsa_public
            lines = [
                "Clé publique de A, publiée : e = %d, n = %s (%d bits)"
                % (e, short(n, 32), n.bit_length()),
                "Clé privée de A : d = %s (conservée par A, jamais envoyée)"
                % short(self.rsa_private[0], 24),
                "Génération des clés : %.0f ms" % self.key_time,
            ]
            hint = ("A calcule H(m) puis la signe avec sa clé PRIVÉE : s = H(m)^d mod n. "
                    "B recalcule H(m) et vérifie avec la clé PUBLIQUE de A : s^e mod n = H(m).")
        else:
            key_a = integrite.secret_partage(self.dh_private_a, self.dh_public_b)
            key_b = integrite.secret_partage(self.dh_private_b, self.dh_public_a)
            lines = [
                "Clés publiques : A = g^a mod p = %s, B = g^b mod p = %s"
                % (short(self.dh_public_a, 20), short(self.dh_public_b, 20)),
                "Clés privées a et b : conservées par A et B, jamais envoyées",
                                "Clé secrète K : A obtient %s, B obtient %s (jamais transmise)"
                % (short(key_a.hex(), 16), short(key_b.hex(), 16)),
            ]
            hint = ("A et B échangent seulement leurs clés publiques (Diffie-Hellman) et calculent "
                    "chacun la même clé secrète K. A envoie m et HMAC(K, m) ; B recalcule le HMAC.")
        set_text(self.keys_box, "\n".join(lines))
        self.hint.config(text=hint)
        set_text(self.result_box, "")
        self.status.config(text="")

    def send(self):
        message = get_text(self.message)
        if not message:
            messagebox.showerror("Erreur", "Le message est vide.")
            return
        algorithm = self.algorithm.get()
        self.digest_a.config(text="Empreinte H(m) : %s" % short(integrite.hacher_hex(message, algorithm)))
        start = time.perf_counter()
        if self.mode.get() == "Signature RSA":
            channel_message = integrite.envoyer_signe(message, self.rsa_private, algorithm)
            proof = "signature RSA"
        else:
            key_a = integrite.secret_partage(self.dh_private_a, self.dh_public_b)
            channel_message = integrite.envoyer_hmac(message, key_a, algorithm)
            proof = "HMAC"
        elapsed = (time.perf_counter() - start) * 1000
        self.channel_box.delete("1.0", "end")
        self.channel_box.insert("1.0", channel_message)
        self.channel_info.config(
            text="Message en clair + %s | hachage : %s | %.2f ms | aucune clé privée transmise"
            % (proof, algorithm, elapsed)
        )
        set_text(self.result_box, "")
        self.status.config(text="message envoyé", foreground="green")

    def tamper_message(self):
        channel_message = get_text(self.channel_box)
        try:
            mode, algorithm, message, proof = integrite.lire_message_canal(channel_message)
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        altered = message.replace("1000", "9000") if "1000" in message else message + "!"
        self.channel_box.delete("1.0", "end")
        self.channel_box.insert(
            "1.0", integrite.construire_message_canal(mode, algorithm, altered, proof)
        )
        self.channel_info.config(text="L'attaquant a modifié le message dans le canal.")

    def tamper_proof(self):
        channel_message = get_text(self.channel_box)
        if "|" not in channel_message:
            messagebox.showerror("Erreur", "Aucun message dans le canal.")
            return
        body, proof = channel_message.rsplit("|", 1)
        flipped = ("1" if proof[-1:] != "1" else "2")
        self.channel_box.delete("1.0", "end")
        self.channel_box.insert("1.0", "%s|%s%s" % (body, proof[:-1], flipped))
        self.channel_info.config(text="L'attaquant a modifié la preuve (signature / HMAC).")

    def receive(self):
        channel_message = get_text(self.channel_box)
        if not channel_message:
            messagebox.showerror("Erreur", "Le canal est vide : rien à vérifier.")
            return
        key_b = integrite.secret_partage(self.dh_private_b, self.dh_public_a)
        try:
            valid, mode, algorithm, message, expected, received = integrite.verification_automatique(
                channel_message, cle_publique_a=self.rsa_public, cle_secrete_b=key_b,
            )
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        if mode == "Signature RSA":
            lines = [
                "Message reçu : %s" % message,
                "Mode détecté : %s | hachage : %s" % (mode, algorithm),
                "H(m) recalculé par B : %s" % short(expected[-64:]),
                "H(m) dans la signature : %s" % short(received[-64:]),
            ]
        else:
            lines = [
                "Message reçu : %s" % message,
                "Mode détecté : %s | hachage : %s" % (mode, algorithm),
                "HMAC recalculé par B : %s" % short(expected),
                "HMAC reçu : %s" % short(received),
            ]
        set_text(self.result_box, "\n".join(lines))
        if valid:
            self.status.config(text="Message intègre et authentique", foreground="green")
        else:
            self.status.config(text="ALERTE : message altéré ou non authentique", foreground="red")


class HashTab(ttk.Frame):
    """Comparaison des fonctions de hachage et effet avalanche."""

    def __init__(self, parent):
        super().__init__(parent, padding=10)
        frame = ttk.LabelFrame(self, text="Texte à hacher", padding=6)
        frame.pack(fill="x")
        self.text = make_text_box(frame, 3)
        self.text.insert("1.0", "Bonjour")
        ttk.Button(frame, text="Calculer les empreintes", command=self.compute).pack(anchor="e", pady=4)

        columns = ("algo", "bits", "status", "time", "digest")
        self.table = ttk.Treeview(self, columns=columns, show="headings", height=6)
        for column, title, width in (
            ("algo", "Algorithme", 170), ("bits", "Taille", 60), ("status", "Sécurité", 210),
            ("time", "Temps (ms)", 90), ("digest", "Empreinte (hex)", 400),
        ):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, anchor="w")
        self.table.pack(fill="x", pady=8)

        avalanche = ttk.LabelFrame(self, text="Effet avalanche : un seul bit du message est inversé", padding=6)
        avalanche.pack(fill="both", expand=True)
        self.avalanche_box = make_text_box(avalanche, 10)
        self.avalanche_box.config(state="disabled")
        self.compute()

    def compute(self):
        text = get_text(self.text)
        self.table.delete(*self.table.get_children())
        lines = []
        for name, (_, bits, status) in integrite.ALGORITHMES.items():
            start = time.perf_counter()
            digest = integrite.hacher_hex(text, name)
            elapsed = (time.perf_counter() - start) * 1000
            self.table.insert("", "end", values=(name, bits, status, "%.3f" % elapsed, digest))
            altered, h1, h2, changed, total = integrite.effet_avalanche(text, name)
            lines.append("%s : %d / %d bits changés (%.1f %%)" % (name, changed, total, 100 * changed / total))
        lines.append("")
        lines.append("Texte original : %r" % text)
        lines.append("Texte modifié  : %r" % integrite.effet_avalanche(text)[0])
        lines.append("Une bonne fonction de hachage change environ 50 % des bits de l'empreinte.")
        same = integrite.sha256_manuel(text).hex() == hashlib.sha256(text.encode("utf-8")).hexdigest()
        lines.append("Vérification : SHA-256 implémenté identique à hashlib.sha256 -> %s"
                     % ("oui" if same else "non"))
        set_text(self.avalanche_box, "\n".join(lines))


def main():
    window = tk.Tk()
    window.title("Framework de chiffrement - SSAD TP1")
    window.geometry("1000x900")
    tabs = ttk.Notebook(window)
    tabs.pack(fill="both", expand=True, padx=6, pady=6)
    tabs.add(IntegrityTab(tabs), text="Intégrité")
    tabs.add(HashTab(tabs), text="Hachage")
    window.mainloop()


if __name__ == "__main__":
    main()
