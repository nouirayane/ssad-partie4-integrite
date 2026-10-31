import tkinter as tk
from tkinter import ttk, messagebox

from partie2 import ciphers
from partie4 import integrite


def read_hill_key(text):
    if "," in text:
        numbers = [int(x) for x in text.split(",")]
        size = int(len(numbers) ** 0.5)
        if size * size != len(numbers):
            raise ValueError("la matrice doit être carrée")
        return [numbers[i * size:(i + 1) * size] for i in range(size)]
    return ciphers.key_from_text(text)


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


class MessagingTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=10)
        self.build_settings()
        self.build_entity_a()
        self.build_channel()
        self.build_entity_b()
        self.change_algorithm()

    def build_settings(self):
        settings = ttk.Frame(self)
        settings.pack(fill="x")
        ttk.Label(settings, text="Algorithme").grid(row=0, column=0)
        self.algorithm = ttk.Combobox(
            settings, values=["Caesar", "Hill", "Playfair"],
            state="readonly", width=12,
        )
        self.algorithm.current(0)
        self.algorithm.grid(row=0, column=1, padx=6)
        self.algorithm.bind("<<ComboboxSelected>>", self.change_algorithm)
        ttk.Label(settings, text="Clé secrète de A").grid(row=0, column=2)
        self.key_a = ttk.Entry(settings, width=22)
        self.key_a.grid(row=0, column=3, padx=6)
        ttk.Label(settings, text="Sens").grid(row=0, column=4)
        self.direction = ttk.Combobox(
            settings, values=["droite", "gauche"], state="readonly", width=8,
        )
        self.direction.current(0)
        self.direction.grid(row=0, column=5, padx=6)
        self.hint = ttk.Label(self, foreground="#555")
        self.hint.pack(anchor="w", pady=6)

    def build_entity_a(self):
        frame = ttk.LabelFrame(self, text="Entité A", padding=6)
        frame.pack(fill="both", expand=True, pady=6)
        self.message = make_text_box(frame, 4)
        self.message.insert("1.0", "Retrouve-moi a la bibliotheque a midi")
        ttk.Button(frame, text="Chiffrer et envoyer", command=self.send).pack(
            anchor="e", pady=4
        )

    def build_channel(self):
        channel = ttk.LabelFrame(self, text="Canal", padding=6)
        channel.pack(fill="both", expand=True, pady=6)
        self.channel_info = ttk.Label(channel, text="Aucun message envoyé.", foreground="#555")
        self.channel_info.pack(anchor="w", pady=(0, 4))
        self.cipher_box = make_text_box(channel, 3)
        self.cipher_box.config(state="disabled")

    def build_entity_b(self):
        frame = ttk.LabelFrame(self, text="Entité B", padding=6)
        frame.pack(fill="both", expand=True, pady=6)
        settings = ttk.Frame(frame)
        settings.pack(fill="x", pady=(0, 4))
        ttk.Label(settings, text="Algorithme détecté automatiquement").pack(side="left")
        self.algorithm_b = ttk.Label(settings, text="non détecté", width=12)
        self.algorithm_b.pack(side="left", padx=6)
        ttk.Label(settings, text="Sens détecté").pack(side="left")
        self.direction_b = ttk.Label(settings, text="non applicable", width=8)
        self.direction_b.pack(side="left", padx=6)

        key_frame = ttk.Frame(frame)
        key_frame.pack(fill="x", pady=(0, 4))
        ttk.Label(key_frame, text="Clé secrète de B (partagée séparément) :").pack(side="left")
        self.key_b = ttk.Entry(key_frame, width=22, show="*")
        self.key_b.pack(side="left", padx=6)
        self.result_box = make_text_box(frame, 4)
        self.result_box.config(state="disabled")
        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=4)
        self.status = ttk.Label(bottom)
        self.status.pack(side="left")
        ttk.Button(bottom, text="Déchiffrer", command=self.receive).pack(side="right")

        self.sent_ciphertext = ""
        self.sent_algorithm = ""
        self.sent_direction = ""
        self.hill_format_positions = []
        self.hill_padding = 0
        self.playfair_format_positions = []
        self.playfair_padding_positions = []
        self.playfair_j_positions = []

    def change_algorithm(self, event=None):
        name = self.algorithm.get()
        settings = {
            "Caesar": ("3", "Clé : décalage n (entier). Le sens s'applique au chiffrement.", "readonly"),
            "Hill": ("3,3,2,5", "Clé : 4 ou 9 nombres séparés par des virgules, ou un mot de 4 ou 9 lettres.", "disabled"),
            "Playfair": ("monarchy", "Clé : un mot quelconque (J est confondu avec I).", "disabled"),
        }
        key, hint, direction_state = settings[name]
        self.key_a.delete(0, "end")
        self.key_a.insert(0, key)
        self.hint.config(text=hint)
        self.direction.config(state=direction_state)
        set_text(self.result_box, "")

    def encrypt(self, text, key_text):
        name = self.algorithm.get()
        key = key_text
        if name == "Caesar":
            return ciphers.caesar(text, int(key), self.direction.get())
        if name == "Hill":
            hill_key = read_hill_key(key)
            letters = ciphers.clean(text)
            self.hill_format_positions = ciphers.format_positions(text.upper())
            self.hill_padding = (-len(letters)) % len(hill_key)
            return ciphers.hill_encrypt(text, hill_key)
        self.playfair_format_positions = ciphers.format_positions(text.upper())
        self.playfair_padding_positions = ciphers.playfair_prepare(text)[1]
        self.playfair_j_positions = ciphers.playfair_j_positions(text)
        return ciphers.playfair_encrypt(text, key)

    def decrypt(self, text, key_text):
        name, direction, _ = ciphers.decode_channel_message(text)
        self.sent_algorithm = name
        self.sent_direction = {"r": "droite", "l": "gauche"}.get(direction, "")
        if name == "Caesar":
            decrypted = ciphers.dechiffrement_automatique(text, key_text)
            return decrypted
        if name == "Hill":
            decrypted = ciphers.dechiffrement_automatique(
                text,
                key_text,
                hill_key=read_hill_key(key_text),
            )
            if self.hill_padding:
                decrypted = decrypted[:-self.hill_padding]
            return ciphers.restore_format(decrypted, self.hill_format_positions)
        decrypted = ciphers.dechiffrement_automatique(text, key_text)
        decrypted = ciphers.playfair_strip_padding(
            decrypted,
            self.playfair_padding_positions,
        )
        decrypted = ciphers.playfair_restore_j(
            decrypted,
            self.playfair_j_positions,
        )
        return ciphers.restore_format(decrypted, self.playfair_format_positions)

    def send(self):
        try:
            encrypted = self.encrypt(get_text(self.message), self.key_a.get().strip())
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        self.sent_algorithm = self.algorithm.get()
        self.sent_direction = self.direction.get()
        channel_message = ciphers.build_channel_message(
            self.sent_algorithm,
            self.sent_direction,
            encrypted,
        )
        set_text(self.cipher_box, channel_message)
        self.sent_ciphertext = channel_message
        self.algorithm_b.config(text=self.sent_algorithm)
        self.direction_b.config(
            text=self.sent_direction if self.sent_algorithm == "Caesar" else "non applicable"
        )
        direction = self.sent_direction if self.sent_algorithm == "Caesar" else "non applicable"
        self.channel_info.config(
            text="Message chiffré | algorithme : %s | sens : %s | clé secrète non transmise"
            % (self.sent_algorithm, direction)
        )
        self.status.config(text="message envoyé", foreground="green")

    def receive(self):
        encrypted = get_text(self.cipher_box)
        if not self.sent_ciphertext:
            messagebox.showerror("Erreur", "Aucun message n'a été envoyé par l'entité A.")
            return
        if not encrypted:
            messagebox.showerror("Erreur", "Le canal est vide : rien à déchiffrer.")
            return
        try:
            decrypted = self.decrypt(encrypted, self.key_b.get().strip())
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        self.status.config(text="message déchiffré", foreground="green")
        set_text(self.result_box, decrypted)


BG = "#e8eff9"
PANEL = "#ffffff"
FIELD = "#f3f7fd"
LABEL_BG = "#e3ecf8"
BLUE = "#2f74d0"
DARK = "#1f2a44"
GREEN_TEXT = "#1d6b3a"
RED = "#c62828"
GREY = "#5b6478"
FONT = "Segoe UI"


def field_label(parent, text):
    tk.Label(parent, text=text, bg=LABEL_BG, fg=GREY, font=(FONT, 9), anchor="w").pack(
        fill="x", pady=(6, 1)
    )


def code_box(parent, height, editable=False):
    box = tk.Text(
        parent, height=height, wrap="char", bg=FIELD, fg=GREEN_TEXT, relief="solid", bd=1,
        highlightthickness=0, font=("Consolas", 9), padx=4, pady=4,
    )
    box.pack(fill="x")
    if not editable:
        box.config(state="disabled")
    return box


def blue_button(parent, text, command):
    return tk.Button(
        parent, text=text, command=command, bg=BLUE, fg="white", activebackground="#245fb0",
        activeforeground="white", relief="flat", font=(FONT, 9, "bold"), pady=6, cursor="hand2",
    )


def light_button(parent, text, command):
    return tk.Button(
        parent, text=text, command=command, bg=FIELD, fg=DARK, relief="solid", bd=1,
        font=(FONT, 9), pady=4, cursor="hand2",
    )


class IntegrityPage(tk.Frame):
    """Partie 4 - possibilité 1 : A envoie C et H = SHA256(C), B recalcule
    H' = SHA256(C') et ne déchiffre que si H = H'."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.chiffrement = integrite.Chiffrement()
        self.original = None
        tk.Label(self, text="Partie 4 — Intégrité avec SHA-256", bg=BG, fg=DARK,
                 font=(FONT, 15, "bold")).pack(anchor="w", padx=6)
        tk.Label(self, text="Alice envoie C et H = SHA256(C). Bob recalcule H' = SHA256(C') : "
                            "il ne déchiffre que si H = H'.",
                 bg=BG, fg=GREY, font=(FONT, 9)).pack(anchor="w", padx=6, pady=(2, 8))
        columns = tk.Frame(self, bg=BG)
        columns.pack(fill="both", expand=True)
        for i in range(3):
            columns.columnconfigure(i, weight=1, uniform="col")
        columns.rowconfigure(0, weight=1)
        self.build_entity_a(self.column(columns, 0, "Entity A — Sender"))
        self.build_channel(self.column(columns, 1, "Transmission Channel"))
        self.build_entity_b(self.column(columns, 2, "Entity B — Receiver"))
        self.change_algorithm()

    def column(self, parent, index, title):
        frame = tk.LabelFrame(parent, text=title, bg=PANEL, fg=DARK, font=(FONT, 9, "bold"),
                              relief="solid", bd=1, labelanchor="nw")
        frame.grid(row=0, column=index, sticky="nsew", padx=6)
        inner = tk.Frame(frame, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        return inner

    def build_entity_a(self, frame):
        field_label(frame, "Récepteur")
        self.receiver = ttk.Combobox(frame, values=["Entité B"], state="readonly")
        self.receiver.current(0)
        self.receiver.pack(fill="x")
        field_label(frame, "Algorithme")
        self.algorithm = ttk.Combobox(frame, values=integrite.ALGORITHMES, state="readonly")
        self.algorithm.current(0)
        self.algorithm.pack(fill="x")
        self.algorithm.bind("<<ComboboxSelected>>", self.change_algorithm)
        field_label(frame, "Clé de chiffrement")
        self.key = tk.Entry(frame, bg=FIELD, relief="solid", bd=1, font=(FONT, 9))
        self.key.pack(fill="x", ipady=2)
        field_label(frame, "Sens (César)")
        self.direction = ttk.Combobox(frame, values=["droite", "gauche"], state="readonly")
        self.direction.current(0)
        self.direction.pack(fill="x")
        field_label(frame, "Message original")
        self.message = tk.Text(frame, height=2, wrap="word", bg=PANEL, relief="solid", bd=1,
                               font=(FONT, 9), padx=4, pady=4)
        self.message.pack(fill="x")
        self.message.insert("1.0", "Retrouve-moi a la bibliotheque a midi")
        blue_button(frame, "\U0001F512  Chiffrer et envoyer", self.send).pack(fill="x", pady=(8, 0))
        field_label(frame, "Message chiffré généré")
        self.cipher_a = code_box(frame, 2)
        field_label(frame, "Generated SHA-256 Hash")
        self.hash_a = code_box(frame, 3)

    def build_channel(self, frame):
        field_label(frame, "Message chiffré (C)")
        self.channel_c = code_box(frame, 3, editable=True)
        field_label(frame, "Hash transmis (H)")
        self.channel_h = code_box(frame, 3)
        light_button(frame, "⚠  Simulate tampering", self.tamper).pack(fill="x", pady=(12, 4))
        light_button(frame, "↻  Reset to original", self.reset).pack(fill="x")
        self.channel_status = tk.Label(frame, bg=PANEL, fg=RED, font=(FONT, 9), justify="left",
                                       anchor="w", wraplength=260)
        self.channel_status.pack(fill="x", pady=(10, 0))

    def build_entity_b(self, frame):
        field_label(frame, "Message chiffré reçu (C')")
        self.cipher_b = code_box(frame, 2)
        field_label(frame, "Hash reçu (H)")
        self.hash_b = code_box(frame, 3)
        field_label(frame, "Computed SHA-256 Hash (H')")
        self.hash_computed = code_box(frame, 3)
        blue_button(frame, "\U0001F513  Vérifier et déchiffrer", self.verify).pack(fill="x", pady=(12, 0))
        self.status = tk.Label(frame, bg=PANEL, font=(FONT, 9, "bold"), justify="left", anchor="w",
                               wraplength=260)
        self.status.pack(fill="x", pady=(8, 0))
        field_label(frame, "Message déchiffré")
        self.result = tk.Text(frame, height=2, wrap="word", bg=PANEL, relief="solid", bd=1,
                              font=(FONT, 9), padx=4, pady=4, state="disabled")
        self.result.pack(fill="x")

    def change_algorithm(self, event=None):
        name = self.algorithm.get()
        self.key.delete(0, "end")
        self.key.insert(0, integrite.CLES_PAR_DEFAUT[name])
        self.direction.config(state="readonly" if name == "Caesar" else "disabled")

    def set_channel_c(self, text):
        self.channel_c.delete("1.0", "end")
        self.channel_c.insert("1.0", text)

    def show_received(self, c, h):
        set_text(self.cipher_b, c)
        set_text(self.hash_b, h)
        set_text(self.hash_computed, "")
        set_text(self.result, "")
        self.status.config(text="")

    def send(self):
        message = get_text(self.message)
        if not message:
            messagebox.showerror("Erreur", "Le message est vide.")
            return
        try:
            c, h = integrite.envoyer(self.chiffrement, self.algorithm.get(), message,
                                     self.key.get().strip(), self.direction.get())
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        self.original = (c, h)
        set_text(self.cipher_a, c)
        set_text(self.hash_a, h)
        self.set_channel_c(c)
        set_text(self.channel_h, h)
        self.channel_status.config(text="")
        self.show_received(c, h)

    def tamper(self):
        if self.original is None:
            messagebox.showerror("Erreur", "Aucun message n'a été envoyé par l'entité A.")
            return
        try:
            c, index, old, new = integrite.falsifier(get_text(self.channel_c))
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        self.set_channel_c(c)
        self.channel_status.config(
            fg=RED,
            text="⚠  Modifié en transit : caractère n°%d du chiffré « %s » → « %s ». "
                 "Le hash transmis est resté celui d'origine." % (index, old, new),
        )
        self.show_received(c, get_text(self.channel_h))

    def reset(self):
        if self.original is None:
            return
        c, h = self.original
        self.set_channel_c(c)
        set_text(self.channel_h, h)
        self.channel_status.config(fg=GREEN_TEXT, text="Canal rétabli : message d'origine.")
        self.show_received(c, h)

    def verify(self):
        if self.original is None:
            messagebox.showerror("Erreur", "Aucun message n'a été envoyé par l'entité A.")
            return
        c, h = get_text(self.channel_c), get_text(self.channel_h)
        self.show_received(c, h)
        try:
            ok, h_computed, plain = integrite.recevoir(self.chiffrement, c, h, self.key.get().strip())
        except ValueError as error:
            messagebox.showerror("Erreur", str(error))
            return
        set_text(self.hash_computed, h_computed)
        if ok:
            self.status.config(fg=GREEN_TEXT, text="✔  Message intègre : H = H'.\nDéchiffrement autorisé.")
            set_text(self.result, plain)
        else:
            self.status.config(fg=RED, text="✖  Message modifié : H ≠ H'.\nDéchiffrement bloqué.")


class CryptoLink(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoLink")
        self.geometry("1220x870")
        self.configure(bg=BG)
        style = ttk.Style(self)
        style.configure("TCombobox", fieldbackground=FIELD)

        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=24, pady=(14, 10))
        tk.Label(header, text="CRYPTO", bg=BG, fg=BLUE, font=(FONT, 17, "bold")).pack(side="left")
        tk.Label(header, text=" LINK", bg=BG, fg=DARK, font=(FONT, 17, "bold")).pack(side="left")
        tk.Label(header, text="SSAD - TP n°1", bg=BG, fg=GREY, font=(FONT, 9)).pack(side="left", padx=24)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        sidebar = tk.Frame(body, bg=PANEL, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True, padx=(18, 0))

        tk.Label(sidebar, text="ESPACE DE TRAVAIL", bg=LABEL_BG, fg=DARK,
                 font=(FONT, 9, "bold")).pack(anchor="w", padx=10, pady=(14, 12))
        messaging = tk.Frame(self.content, bg=BG)
        MessagingTab(messaging).pack(fill="both", expand=True)
        self.pages = {"Envoyer un message": messaging, "Intégrité (SHA-256)": IntegrityPage(self.content)}
        self.buttons = {}
        for name in self.pages:
            button = tk.Button(sidebar, text=name, relief="solid", bd=1, font=(FONT, 9),
                               cursor="hand2", pady=5, command=lambda n=name: self.show(n))
            button.pack(fill="x", padx=10, pady=4)
            self.buttons[name] = button
        tk.Frame(sidebar, bg="#c9d3e3", height=1).pack(fill="x", padx=10, pady=14)
        tk.Label(sidebar, text="La clé de chiffrement n'est jamais envoyée dans le canal : "
                               "seuls C et H = SHA256(C) y circulent.",
                 bg=LABEL_BG, fg=GREY, font=(FONT, 9), wraplength=190, justify="left").pack(padx=10, anchor="w")
        self.show("Intégrité (SHA-256)")

    def show(self, name):
        for page_name, page in self.pages.items():
            page.pack_forget()
            active = page_name == name
            self.buttons[page_name].config(
                bg=BLUE if active else FIELD, fg="white" if active else DARK,
                font=(FONT, 9, "bold" if active else "normal"),
            )
        self.pages[name].pack(fill="both", expand=True)


def main():
    CryptoLink().mainloop()


if __name__ == "__main__":
    main()
