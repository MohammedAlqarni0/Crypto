import random
import hashlib
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk

# Miller-Rabin test
def miller_rabin(n, k=10):
    if n < 2: return False
    if n <= 3: return True
    if n % 2 == 0: return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for i in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for j in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

# Extended Euclidean Algorithm
def extended_gcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y

# Generate prime numbers
def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if p % 2 == 0:
            p += 1
        if miller_rabin(p):
            return p

# RSA key generation
def generate_keys(bits):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  #public exponent
    g, x, y = extended_gcd(e, phi)

    if x < 0:
        d = x + phi
    else:
        d = x

    return (e, d, n)


def encrypt(message, e, n):
    m = int.from_bytes(message.encode(), byteorder='big')
    c = pow(m, e, n)
    return c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')


def decrypt(ciphertext, d, n):
    c = int.from_bytes(ciphertext, byteorder='big')
    m = pow(c, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode()


def sign(message, d, n):
    m = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big')
    signature = pow(m, d, n)
    return signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')


def verify(message, signature, e, n):
    s = int.from_bytes(signature, byteorder='big')
    m = pow(s, e, n)
    hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big')
    return m == hash_value

# GUI
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption/Decryption and Digital Signature")
        self.root.geometry("700x500")
        
        # Generate RSA keys
        bits = 2048
        self.e, self.d, self.n = generate_keys(bits)

        # Set the theme
        style = ttk.Style(self.root)
        style.theme_use("clam")  # Use a built-in theme like "clam"

        # Configure main frame
        self.mainframe = ttk.Frame(self.root, padding="10 10 10 10")
        self.mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Message input
        self.message_label = ttk.Label(self.mainframe, text="Message:")
        self.message_label.grid(column=0, row=0, sticky=tk.W, pady=5)
        self.message_text = scrolledtext.ScrolledText(self.mainframe, wrap=tk.WORD, width=70, height=5, font=("Helvetica", 10))
        self.message_text.grid(column=0, row=1, pady=5)

        # Encrypt button
        self.encrypt_button = ttk.Button(self.mainframe, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.grid(column=0, row=2, pady=5)

        # Ciphertext output
        self.ciphertext_label = ttk.Label(self.mainframe, text="Ciphertext:")
        self.ciphertext_label.grid(column=0, row=3, sticky=tk.W, pady=5)
        self.ciphertext_text = scrolledtext.ScrolledText(self.mainframe, wrap=tk.WORD, width=70, height=5, font=("Helvetica", 10))
        self.ciphertext_text.grid(column=0, row=4, pady=5)

        # Decrypt button
        self.decrypt_button = ttk.Button(self.mainframe, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.grid(column=0, row=5, pady=5)

        # Decrypted message output
        self.decrypted_message_label = ttk.Label(self.mainframe, text="Decrypted Message:")
        self.decrypted_message_label.grid(column=0, row=6, sticky=tk.W, pady=5)
        self.decrypted_message_text = scrolledtext.ScrolledText(self.mainframe, wrap=tk.WORD, width=70, height=5, font=("Helvetica", 10))
        self.decrypted_message_text.grid(column=0, row=7, pady=5)

        # Sign button
        self.sign_button = ttk.Button(self.mainframe, text="Sign", command=self.sign_message)
        self.sign_button.grid(column=0, row=8, pady=5)

        # Signature output
        self.signature_label = ttk.Label(self.mainframe, text="Signature:")
        self.signature_label.grid(column=0, row=9, sticky=tk.W, pady=5)
        self.signature_text = scrolledtext.ScrolledText(self.mainframe, wrap=tk.WORD, width=70, height=5, font=("Helvetica", 10))
        self.signature_text.grid(column=0, row=10, pady=5)

        # Verify button
        self.verify_button = ttk.Button(self.mainframe, text="Verify", command=self.verify_signature)
        self.verify_button.grid(column=0, row=11, pady=5)

    def encrypt_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        ciphertext = encrypt(message, self.e, self.n)
        self.ciphertext_text.delete("1.0", tk.END)
        self.ciphertext_text.insert(tk.END, ciphertext.hex())

    def decrypt_message(self):
        ciphertext_hex = self.ciphertext_text.get("1.0", tk.END).strip()
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_message = decrypt(ciphertext, self.d, self.n)
        self.decrypted_message_text.delete("1.0", tk.END)
        self.decrypted_message_text.insert(tk.END, decrypted_message)

    def sign_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        signature = sign(message, self.d, self.n)
        self.signature_text.delete("1.0", tk.END)
        self.signature_text.insert(tk.END, signature.hex())

    def verify_signature(self):
        message = self.message_text.get("1.0", tk.END).strip()
        signature_hex = self.signature_text.get("1.0", tk.END).strip()
        signature = bytes.fromhex(signature_hex)
        if verify(message, signature, self.e, self.n):
            messagebox.showinfo("Signature Verification", "Signature is valid.")
        else:
            messagebox.showinfo("Signature Verification", "Signature is invalid.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
