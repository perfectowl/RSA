import tkinter as tk
from tkinter import ttk
import random
from sympy import gcd, randprime, isprime


# Функции для работы с числами и RSA
def generate_prime(bits=8):
    return randprime(2**(bits-1), 2**bits)


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


# генерация RSA-ключей заданного размера
def generate_keys(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def rsa_encrypt(message, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]


def rsa_decrypt(cipher, private_key):
    d, n = private_key
    return ''.join(chr(pow(char, d, n)) for char in cipher)

# Начальные RSA-ключи
public_key, private_key = None, None

# Функции для обработки событий


def update_keys():
    global public_key, private_key
    public_key, private_key = generate_keys(8)
    public_key_display.configure(state="normal")
    public_key_display.delete("1.0", tk.END)
    public_key_display.insert("1.0", f"{public_key[0]} {public_key[1]}")
    public_key_display.configure(state="disabled")
    private_key_display.configure(state="normal")
    private_key_display.delete("1.0", tk.END)
    private_key_display.insert("1.0", f"{private_key[0]} {private_key[1]}")
    private_key_display.configure(state="disabled")


def encrypt_message():
    try:
        if public_key is None:
            result_output.set("Ошибка: ключи не сгенерированы >:(")
            return
        text = message_input.get("1.0", tk.END).strip()
        encrypted_text = rsa_encrypt(text, public_key)
        result_output.set(' '.join(map(str, encrypted_text)))
    except Exception as e:
        result_output.set(f"Ошибка: {e}")


def decrypt_message():
    try:
        if private_key is None:
            decrypted_output.set("Ошибка: ключи не сгенерированы >:(")
            return
        text = encrypted_input.get("1.0", tk.END).strip()
        cipher = list(map(int, text.split()))
        decrypted_text = rsa_decrypt(cipher, private_key)
        decrypted_output.set(decrypted_text)
    except Exception as e:
        decrypted_output.set(f"Ошибка: {e}")


def copy(content):
    root.clipboard_clear()
    root.clipboard_append(content)
    root.update()


def paste(entry):
    entry.delete("1.0", tk.END)
    entry.insert("1.0", root.clipboard_get())


# Создание интерфейса приложения
root = tk.Tk()
root.title("Шифр RSA")
root.geometry("600x700")

# Ввод сообщения
message_frame = ttk.Frame(root)
message_frame.pack(pady=5, fill=tk.X)
ttk.Label(message_frame, text="Введите сообщение:").pack(anchor=tk.W)
message_input = tk.Text(message_frame, height=4, wrap=tk.WORD)
message_input.pack(fill=tk.BOTH, padx=5, expand=True)

ttk.Button(message_frame, text="Копировать", command=lambda: copy(message_input.get("1.0", tk.END).strip())).pack(side=tk.LEFT, padx=2)
ttk.Button(message_frame, text="Вставить", command=lambda: paste(message_input)).pack(side=tk.LEFT, padx=2)

# Генерация ключей
key_frame = ttk.Frame(root)
key_frame.pack(pady=5, fill=tk.X)
ttk.Button(key_frame, text="Сгенерировать ключи", command=update_keys).pack(pady=5)

# Отображение публичного ключа
ttk.Label(key_frame, text="Публичный ключ:").pack(anchor=tk.W)
public_key_display = tk.Text(key_frame, height=1, wrap=tk.WORD, state="disabled")
public_key_display.pack(fill=tk.BOTH, padx=5, expand=True)

# Отображение приватного ключа
ttk.Label(key_frame, text="Приватный ключ:").pack(anchor=tk.W)
private_key_display = tk.Text(key_frame, height=1, wrap=tk.WORD, state="disabled")
private_key_display.pack(fill=tk.BOTH, padx=5, expand=True)

# Кнопка шифрования
encrypt_button = ttk.Button(root, text="Зашифровать", command=encrypt_message)
encrypt_button.pack(pady=5)

# Поле для вывода зашифрованного текста
result_frame = ttk.Frame(root)
result_frame.pack(pady=5, fill=tk.X)
result_output = tk.StringVar()
result_label = ttk.Label(result_frame, textvariable=result_output, foreground="blue", wraplength=550, anchor=tk.W, justify=tk.LEFT)
result_label.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(result_frame, text="Копировать", command=lambda: copy(result_output.get())).pack(side=tk.LEFT, padx=5)

# Ввод зашифрованного текста
encrypted_frame = ttk.Frame(root)
encrypted_frame.pack(pady=5, fill=tk.X)
ttk.Label(encrypted_frame, text="Введите зашифрованное сообщение:").pack(anchor=tk.W)
encrypted_input = tk.Text(encrypted_frame, height=4, wrap=tk.WORD)
encrypted_input.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(encrypted_frame, text="Копировать", command=lambda: copy(encrypted_input.get("1.0", tk.END).strip())).pack(side=tk.LEFT, padx=2)
ttk.Button(encrypted_frame, text="Вставить", command=lambda: paste(encrypted_input)).pack(side=tk.LEFT, padx=2)

# Кнопка дешифрования
decrypt_button = ttk.Button(root, text="Расшифровать", command=decrypt_message)
decrypt_button.pack(pady=5)

# Поле для вывода расшифрованного текста
decrypted_output = tk.StringVar()
decrypted_label = ttk.Label(root, textvariable=decrypted_output, foreground="green", wraplength=550, anchor=tk.W, justify=tk.LEFT)
decrypted_label.pack(fill=tk.BOTH, padx=5, expand=True)

# Запуск приложения
root.mainloop()
