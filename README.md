# Stego_tool
# 🕷️ Noir Stego Tool — Digital Forensics Utility


Author      : Radhesh Mutreja  
Technique   : Caesar Cipher + LSB Steganography  
GUI         : Tkinter  


## 📌 Overview

Noir Stego Tool is a Digital Forensics utility that combines classical encryption with image steganography.

This tool allows users to:
- Encrypt a message using a Caesar Cipher
- Hide the encrypted message inside an image using LSB (Least Significant Bit) steganography
- Extract and decrypt hidden messages using the correct shift key

This project was developed for educational and forensic demonstration purposes.

---

## 🎯 Features

- Caesar Cipher encryption and decryption
- LSB-based image steganography
- PNG / JPG image support
- Message size validation based on image capacity
- Multithreaded encoding and decoding
- User-friendly Tkinter GUI

---

## 🧠 How It Works

### 1️⃣ Encryption Phase
The plaintext message is encrypted using a Caesar Cipher with a user-defined shift key.

### 2️⃣ Encoding Phase
- The encrypted text is converted into binary.
- A unique end marker (`<<<END>>>`) is appended.
- Each bit is embedded into the least significant bit of image pixel RGB channels.

### 3️⃣ Decoding Phase
- LSB bits are extracted from the image.
- Binary data is reconstructed into text.
- The Caesar Cipher shift is reversed to reveal the original message.

---

## 🛠️ Technologies Used

- Python 3.x
- Tkinter
- Pillow (PIL)
- NumPy
- Threading module

---
