"""
Password Locker (Tkinter) — Plain JSON or AES-GCM Encrypted on Exit

Features:
- Store service, login, password, URL
- Save as plain JSON, or encrypt using AES-GCM with a passcode
- No passcode is ever stored; only random salt + nonce + ciphertext (base64)
- Reveal/Hide toggle for password entry in the form
- Modal passcode dialogs (with Show/Hide) that never hide behind the main window

Requires:
    pip install cryptography
"""

import os
import sys
import json
import base64
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser

# --- Crypto (AES-GCM + scrypt KDF) ---
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_TITLE = "Password Locker (AES-GCM)"
DATA_FILE = "passwords.json"

# ---------- Base64 helpers ----------


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# ---------- KDF & Cipher ----------


def _derive_key(passcode: str, salt: bytes) -> bytes:
    # scrypt parameters balanced for desktop; you can raise n for stronger defense
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passcode.encode("utf-8"))


def encrypt_json_with_passcode(data_obj: list, passcode: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(passcode, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce as recommended for GCM
    plaintext = json.dumps(data_obj, ensure_ascii=False).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=None)
    return {
        "enc": "AESGCM",
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ct": _b64e(ciphertext),
    }


def decrypt_json_with_passcode(blob: dict, passcode: str) -> list:
    if not (isinstance(blob, dict) and blob.get("enc") == "AESGCM"):
        raise ValueError("Not an AES-GCM blob.")
    salt = _b64d(blob["salt"])
    nonce = _b64d(blob["nonce"])
    ct = _b64d(blob["ct"])
    key = _derive_key(passcode, salt)
    aes = AESGCM(key)
    # raises on wrong pass
    plaintext = aes.decrypt(nonce, ct, associated_data=None)
    obj = json.loads(plaintext.decode("utf-8"))
    if not isinstance(obj, list):
        raise ValueError("Decrypted data is not a list.")
    return obj

# ---------- Modal passcode dialog with Show/Hide ----------


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title="Enter Passcode", prompt="Enter:", confirm=False):
        super().__init__(parent)
        self.parent = parent
        self.title(title)
        self.resizable(False, False)

        self.result = None
        self._show = tk.BooleanVar(value=False)

        # Make truly modal & on top of parent
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=prompt).grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(frm, show="*")
        self.entry.grid(row=1, column=0, columnspan=2,
                        sticky="ew", pady=(4, 8))
        frm.columnconfigure(0, weight=1)

        self.confirm = None
        if confirm:
            ttk.Label(frm, text="Confirm:").grid(row=2, column=0, sticky="w")
            self.confirm = ttk.Entry(frm, show="*")
            self.confirm.grid(row=3, column=0, columnspan=2,
                              sticky="ew", pady=(4, 8))

        chk = ttk.Checkbutton(
            frm, text="Show", variable=self._show, command=self._toggle_show)
        chk.grid(row=4, column=0, sticky="w", pady=(0, 8))

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, sticky="e")
        ok = ttk.Button(btns, text="OK", command=self._on_ok)
        ok.pack(side="left", padx=(0, 6))
        cancel = ttk.Button(btns, text="Cancel", command=self._on_cancel)
        cancel.pack(side="left")

        # Center relative to parent
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.entry.focus_set()

    def _toggle_show(self):
        show = "" if self._show.get() else "*"
        self.entry.config(show=show)
        if self.confirm is not None:
            self.confirm.config(show=show)

    def _on_ok(self):
        pw = self.entry.get()
        if self.confirm is not None:
            pw2 = self.confirm.get()
            if pw != pw2:
                messagebox.showerror(
                    "Mismatch", "Passcodes do not match.", parent=self)
                return
        self.result = pw
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


def ask_password(parent, title, prompt, confirm=False):
    dlg = PasswordDialog(parent, title=title, prompt=prompt, confirm=confirm)
    parent.wait_window(dlg)
    return dlg.result

# ---------- Main App ----------


class PasswordLockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x500")
        self.minsize(800, 450)

        self.entries = self._load_data()

        self._build_widgets()
        self._populate_table()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # --------- File I/O ---------
    def _load_data(self):
        """Load entries from DATA_FILE.
        Behavior:
        - If the file is plain JSON list -> load it.
        - If it's an AES-GCM blob -> prompt for passcode and decrypt.
        - If user cancels unlock -> return [] (empty list in memory).
        """
        if not os.path.exists(DATA_FILE):
            return []

        with open(DATA_FILE, "rb") as f:
            raw = f.read()

        # Try to parse as JSON text first
        try:
            text = raw.decode("utf-8")
            doc = json.loads(text)
            if isinstance(doc, list):
                return doc
            if isinstance(doc, dict) and doc.get("enc") == "AESGCM":
                # Encrypted wrapper; prompt for passcode
                while True:
                    passcode = ask_password(
                        self, "Unlock", "Enter passcode to decrypt:", confirm=False)
                    if passcode is None:
                        return []
                    try:
                        return decrypt_json_with_passcode(doc, passcode)
                    except Exception:
                        retry = messagebox.askretrycancel(
                            "Decrypt Failed",
                            "Wrong passcode or file corrupted.\nTry again?",
                            parent=self
                        )
                        if not retry:
                            return []
        except Exception:
            # Not valid JSON at all
            messagebox.showerror(
                "Load Error", "Unrecognized file format.", parent=self)
            return []

        # If JSON but not a list or AES blob
        messagebox.showerror(
            "Load Error", "JSON file format is invalid.", parent=self)
        return []

    def _save_plain(self):
        payload = json.dumps(self.entries, indent=2, ensure_ascii=False)
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            f.write(payload)

    def _save_encrypted(self, passcode: str):
        blob = encrypt_json_with_passcode(self.entries, passcode)
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(blob, f, indent=2, ensure_ascii=False)

    # --------- UI Layout ---------
    def _build_widgets(self):
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)

        columns = ("service", "login", "password", "url")
        self.tree = ttk.Treeview(
            root, columns=columns, show="headings", height=12)
        for col, label, w in [
            ("service", "Service", 200),
            ("login", "Login", 180),
            ("password", "Password", 180),
            ("url", "URL", 300),
        ]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=w, anchor="w")

        yscroll = ttk.Scrollbar(root, orient="vertical",
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.grid(row=0, column=0, columnspan=6, sticky="nsew")
        yscroll.grid(row=0, column=6, sticky="ns")

        form = ttk.LabelFrame(root, text="Entry")
        form.grid(row=1, column=0, columnspan=7, sticky="ew", pady=(10, 5))
        for i in range(9):
            form.columnconfigure(i, weight=1)

        ttk.Label(form, text="Service:").grid(row=0, column=0, sticky="e")
        self.service_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.service_var).grid(
            row=0, column=1, sticky="ew", padx=5)

        ttk.Label(form, text="Login:").grid(row=0, column=2, sticky="e")
        self.login_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.login_var).grid(
            row=0, column=3, sticky="ew", padx=5)

        ttk.Label(form, text="Password:").grid(row=0, column=4, sticky="e")
        self.password_var = tk.StringVar()
        pwd_entry = ttk.Entry(form, textvariable=self.password_var, show="*")
        pwd_entry.grid(row=0, column=5, sticky="ew", padx=5)

        # Reveal/Hide toggle for password field
        self._pwd_shown = tk.BooleanVar(value=False)

        def toggle_form_pwd():
            pwd_entry.config(show="" if self._pwd_shown.get() else "*")
        ttk.Checkbutton(form, text="Show", variable=self._pwd_shown, command=toggle_form_pwd)\
            .grid(row=0, column=6, sticky="w")

        ttk.Label(form, text="URL:").grid(row=0, column=7, sticky="e")
        self.url_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.url_var).grid(
            row=0, column=8, sticky="ew", padx=5)

        btns = ttk.Frame(root)
        btns.grid(row=2, column=0, columnspan=7, sticky="ew", pady=(5, 0))
        for i in range(12):
            btns.columnconfigure(i, weight=1)

        ttk.Button(btns, text="Add", command=self.add_entry).grid(
            row=0, column=0, padx=4, sticky="ew")
        ttk.Button(btns, text="Update Selected", command=self.update_selected).grid(
            row=0, column=1, padx=4, sticky="ew")
        ttk.Button(btns, text="Delete Selected", command=self.delete_selected).grid(
            row=0, column=2, padx=4, sticky="ew")
        ttk.Button(btns, text="Copy Password", command=self.copy_password).grid(
            row=0, column=3, padx=4, sticky="ew")
        ttk.Button(btns, text="Open URL", command=self.open_url).grid(
            row=0, column=4, padx=4, sticky="ew")
        ttk.Button(btns, text="Save (Plain JSON)", command=lambda: self.save(
            False)).grid(row=0, column=5, padx=4, sticky="ew")
        ttk.Button(btns, text="Save Encrypted…", command=lambda: self.save(
            True)).grid(row=0, column=6, padx=4, sticky="ew")

        root.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _populate_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for entry in self.entries:
            self.tree.insert("", "end", values=(
                entry.get("service", ""),
                entry.get("login", ""),
                entry.get("password", ""),
                entry.get("url", ""),
            ))

    # --------- CRUD ---------
    def _entry_from_form(self):
        return {
            "service": self.service_var.get().strip(),
            "login": self.login_var.get().strip(),
            "password": self.password_var.get(),
            "url": self.url_var.get().strip(),
        }

    def _validate_entry(self, e):
        if not e["service"]:
            messagebox.showwarning(
                "Validation", "Service is required.", parent=self)
            return False
        return True

    def add_entry(self):
        e = self._entry_from_form()
        if not self._validate_entry(e):
            return
        self.entries.append(e)
        self._populate_table()
        self._clear_form()

    def update_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(
                "Update", "Select a row to update.", parent=self)
            return
        index = self.tree.index(sel[0])
        e = self._entry_from_form()
        if not self._validate_entry(e):
            return
        self.entries[index] = e
        self._populate_table()

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(
                "Delete", "Select a row to delete.", parent=self)
            return
        index = self.tree.index(sel[0])
        if messagebox.askyesno("Delete", "Delete the selected entry?", parent=self):
            self.entries.pop(index)
            self._populate_table()
            self._clear_form()

    def copy_password(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Copy", "Select a row first.", parent=self)
            return
        index = self.tree.index(sel[0])
        pwd = self.entries[index].get("password", "")
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.update()  # keep clipboard contents after close
        messagebox.showinfo(
            "Copied", "Password copied to clipboard.", parent=self)

    def open_url(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Open URL", "Select a row first.", parent=self)
            return
        index = self.tree.index(sel[0])
        url = self.entries[index].get("url", "").strip()
        if not url:
            messagebox.showinfo(
                "Open URL", "No URL for this entry.", parent=self)
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url
        try:
            webbrowser.open(url)
        except Exception as ex:
            messagebox.showerror(
                "Open URL", f"Failed to open URL:\n{ex}", parent=self)

    def _clear_form(self):
        self.service_var.set("")
        self.login_var.set("")
        self.password_var.set("")
        self.url_var.set("")

    def _on_tree_select(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        index = self.tree.index(sel[0])
        e = self.entries[index]
        self.service_var.set(e.get("service", ""))
        self.login_var.set(e.get("login", ""))
        self.password_var.set(e.get("password", ""))
        self.url_var.set(e.get("url", ""))

    # --------- Saving / Closing ---------
    def save(self, encrypt=False):
        if encrypt:
            passcode = ask_password(
                self, "Encrypt & Save", "Enter passcode:", confirm=True)
            if passcode is None:
                return
            try:
                self._save_encrypted(passcode)
                messagebox.showinfo(
                    "Saved", f"Encrypted data saved to {DATA_FILE}.", parent=self)
            except Exception as ex:
                messagebox.showerror("Save Error", str(ex), parent=self)
        else:
            try:
                self._save_plain()
                messagebox.showinfo(
                    "Saved", f"Plain JSON saved to {DATA_FILE}.", parent=self)
            except Exception as ex:
                messagebox.showerror("Save Error", str(ex), parent=self)

    def on_close(self):
        choice = messagebox.askyesnocancel(
            "Encrypt before exit?",
            "Encrypt your data with a passcode before closing?\n\nYes = Encrypt & Save\nNo = Save as plain JSON\nCancel = Stay in app",
            parent=self
        )
        if choice is None:
            return
        if choice:
            passcode = ask_password(
                self, "Encrypt & Exit", "Enter passcode:", confirm=True)
            if passcode is None:
                return
            try:
                self._save_encrypted(passcode)
            except Exception as ex:
                messagebox.showerror("Save Error", str(ex), parent=self)
                return
        else:
            try:
                self._save_plain()
            except Exception as ex:
                messagebox.showerror("Save Error", str(ex), parent=self)
                return
        # Clean shutdown
        try:
            self.destroy()
            self.update_idletasks()
        except Exception:
            pass
        self.after(50, self.quit)


def main():
    # Optional: nicer DPI scaling on Windows
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    app = PasswordLockerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
