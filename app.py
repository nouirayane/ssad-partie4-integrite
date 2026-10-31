import tkinter as tk
from tkinter import ttk, messagebox

from partie4 import integrite


def set_text(box, text):
    box.config(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", text)
    box.config(state="disabled")


def get_text(box):
    return box.get("1.0", "end").strip()


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
        tk.Label(sidebar, text="Intégrité (SHA-256)", bg=BLUE, fg="white", relief="solid", bd=1,
                 font=(FONT, 9, "bold"), pady=5).pack(fill="x", padx=10, pady=4)
        self.page = IntegrityPage(self.content)
        self.page.pack(fill="both", expand=True)
        tk.Frame(sidebar, bg="#c9d3e3", height=1).pack(fill="x", padx=10, pady=14)
        tk.Label(sidebar, text="La clé de chiffrement n'est jamais envoyée dans le canal : "
                               "seuls C et H = SHA256(C) y circulent.",
                 bg=LABEL_BG, fg=GREY, font=(FONT, 9), wraplength=190, justify="left").pack(padx=10, anchor="w")


def main():
    CryptoLink().mainloop()


if __name__ == "__main__":
    main()
