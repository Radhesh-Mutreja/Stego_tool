"""
=========================================================
🕷️ NOIR STEGO TOOL — DIGITAL FORENSICS UTILITY
---------------------------------------------------------
Author      : Radhesh Mutreja
Course      : DFIS
Technique   : Caesar Cipher + LSB Steganography
GUI         : Tkinter
=========================================================
"""

# =========================
# STANDARD LIBRARIES
# =========================
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import os

# =========================
# IMAGE / NUMPY LIBRARIES
# =========================
from PIL import Image
import numpy as np


# =========================
# GLOBAL VARIABLES
# =========================
selected_image_path = None
OUTPUT_IMAGE_NAME = "stego_output.png"
END_MARKER = "<<<END>>>"


# ======================================================
# UI HELPER FUNCTIONS
# ======================================================

def show_error(msg):
    messagebox.showerror("Error", msg)


def show_info(msg):
    messagebox.showinfo("Info", msg)


# ======================================================
# IMAGE SELECTION
# ======================================================

def choose_image():
    global selected_image_path

    path = filedialog.askopenfilename(
        title="Select Image",
        filetypes=[("Image Files", "*.png *.jpg *.jpeg")]
    )

    if path:
        selected_image_path = path
        image_label.config(text=f"Selected Image:\n{os.path.basename(path)}")


# ======================================================
# CAESAR CIPHER LOGIC
# ======================================================

def caesar_encrypt(text, shift):
    """
    Encrypt text using Caesar Cipher
    """
    result = ""

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char

    return result


def caesar_decrypt(text, shift):
    """
    Decrypt Caesar Cipher text
    """
    return caesar_encrypt(text, -shift)


# ======================================================
# TEXT <-> BINARY
# ======================================================

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)


def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)


# ======================================================
# STEGANOGRAPHY CORE
# ======================================================

def encode_text_in_image(image_path, secret_text, shift, output_path):
    """
    Encrypts text → hides it in image (LSB)
    """

    encrypted_text = caesar_encrypt(secret_text, shift)
    encrypted_text += END_MARKER

    binary_text = text_to_binary(encrypted_text)

    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    h, w, _ = pixels.shape
    capacity = h * w * 3

    if len(binary_text) > capacity:
        raise ValueError("Message too large for this image.")

    idx = 0

    for row in range(h):
        for col in range(w):
            for channel in range(3):
                if idx < len(binary_text):
                    bit = int(binary_text[idx])
                    pixels[row, col, channel] = (
                        pixels[row, col, channel] & 254
                    ) | bit
                    idx += 1

    Image.fromarray(pixels).save(output_path)


def decode_text_from_image(image_path, shift):
    """
    Extracts and decrypts hidden message
    """

    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    binary = ""

    for row in range(pixels.shape[0]):
        for col in range(pixels.shape[1]):
            for channel in range(3):
                binary += str(pixels[row, col, channel] & 1)

    text = binary_to_text(binary)

    if END_MARKER not in text:
        return "No hidden message found."

    encrypted = text.split(END_MARKER)[0]
    return caesar_decrypt(encrypted, shift)


# ======================================================
# GUI ACTIONS
# ======================================================

def encode_action():
    if not selected_image_path:
        show_error("Select an image first.")
        return

    text = text_box.get("1.0", tk.END).strip()
    shift = shift_entry.get().strip()

    if not text or not shift.isdigit():
        show_error("Enter message and numeric shift value.")
        return

    try:
        encode_text_in_image(
            selected_image_path,
            text,
            int(shift),
            OUTPUT_IMAGE_NAME
        )
        show_info(f"Message encrypted & hidden!\nSaved as {OUTPUT_IMAGE_NAME}")
    except Exception as e:
        show_error(str(e))


def decode_action():
    if not selected_image_path:
        show_error("Select an image first.")
        return

    shift = shift_entry.get().strip()

    if not shift.isdigit():
        show_error("Enter correct shift key.")
        return

    try:
        message = decode_text_from_image(
            selected_image_path,
            int(shift)
        )
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, message)
    except Exception as e:
        show_error(str(e))


# ======================================================
# THREADING
# ======================================================

def threaded_encode():
    threading.Thread(target=encode_action, daemon=True).start()


def threaded_decode():
    threading.Thread(target=decode_action, daemon=True).start()


# ======================================================
# GUI SETUP
# ======================================================

root = tk.Tk()
root.title("🕷️ Noir Stego Tool — DFIS Utility")
root.geometry("850x650")
root.resizable(False, False)

title = tk.Label(
    root,
    text="NOIR STEGO TOOL",
    font=("Consolas", 20, "bold")
)
title.pack(pady=10)

subtitle = tk.Label(
    root,
    text="Caesar Cipher + LSB Steganography",
    font=("Consolas", 10)
)
subtitle.pack()

# Image selection
tk.Button(
    root,
    text="Select Image",
    width=20,
    command=choose_image
).pack(pady=10)

image_label = tk.Label(
    root,
    text="No image selected",
    font=("Consolas", 9)
)
image_label.pack()

# Shift key
shift_frame = tk.Frame(root)
shift_frame.pack(pady=5)

tk.Label(
    shift_frame,
    text="Caesar Shift Key:",
    font=("Consolas", 10)
).pack(side=tk.LEFT)

shift_entry = tk.Entry(
    shift_frame,
    width=10
)
shift_entry.pack(side=tk.LEFT, padx=10)

# Text box
text_box = scrolledtext.ScrolledText(
    root,
    width=95,
    height=15,
    font=("Consolas", 10)
)
text_box.pack(pady=15)

# Buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(
    btn_frame,
    text="Encode & Hide",
    width=20,
    command=threaded_encode
).grid(row=0, column=0, padx=15)

tk.Button(
    btn_frame,
    text="Decode & Decrypt",
    width=20,
    command=threaded_decode
).grid(row=0, column=1, padx=15)

# Footer
tk.Label(
    root,
    text="Educational Use Only | Digital Forensics Project \n© 2026 Radhesh Mutreja",
    font=("Consolas", 8)
).pack(side=tk.BOTTOM, pady=10)

root.mainloop()
