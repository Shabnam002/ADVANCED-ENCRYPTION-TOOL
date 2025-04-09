# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: SHABNAM SHARMA

*INTERN ID*: CT12WE04

*DOMAIN*: CYBER SECURITY & ETHICAL HACKING

*DURATION*: 12 WEEKS

*MENTOR*: NEELA SANTOSH KUMAR

# DESCRPTION OF TASK 

# BUILD A TOOL TO ENCRYPT AND DECRYPT FILES USING ADVANCED ALGORITHMS LIKES AES-256

# A ROBUST ENCRYPTION APPLICATION WITH A USER-FRIENDLY INTERFACE

# INTRODUCTION

In the modern digital landscape, securing sensitive information is not just a recommendation — it's a necessity. Whether it's academic records, business reports, financial documents, or personal files, data is constantly at risk of unauthorized access, misuse, or breaches. This project aims to address that concern by developing a Python-based tool that encrypts and decrypts files using AES-256 (Advanced Encryption Standard) — a symmetric encryption algorithm known for its robustness and reliability in both government and industry-grade applications.

This tool allows users to easily convert any file into a secure, unreadable format (encryption) and later restore it to its original state (decryption) using a password. The integration of AES-256 ensures that the encryption is virtually unbreakable without the correct key, providing strong protection against data theft.

# Real-Life Use Case

Consider a scenario where a working professional stores confidential documents — such as client contracts, business plans, or identification records — on a personal laptop. In case the system is lost, stolen, or compromised, these files could be exploited. However, if the files were encrypted using this tool, they would be rendered unreadable and useless to anyone without the correct password. This simple layer of protection can prevent serious privacy breaches and data leaks.

By offering a user-friendly interface and leveraging military-grade encryption, this project demonstrates how powerful security can be made accessible to everyday users.

# KEY FEATURES

1. AES-256 Encryption: Uses strong, military-grade encryption for maximum security.

2. Password Protection: Files can only be accessed with the correct password.

3. File Encryption/Decryption: Supports all file types — encrypts and restores them safely.

4. User-Friendly: Simple command-line interface; easy for anyone to use.

5. Safe Output Naming: Adds .enc for encrypted and .dec for decrypted files to avoid confusion.

6. Cross-Platform: Works on Windows, macOS, and Linux with Python installed.

# Process of Encryption 

1. User Input
The user runs the tool and chooses the encryption option (E) from the menu.

2. File Selection
The user enters the name/path of the file they want to encrypt (e.g., example.txt).

3. Password Entry
The tool asks the user to enter a password. This password is used to create a secure encryption key.

4. Key Derivation
A cryptographic key is derived from the password using a secure algorithm. This key is used to lock the file.

5. File Reading
The tool reads the content of the original file in binary format.

6. AES-256 Encryption
The file content is encrypted using the AES-256 algorithm, turning it into unreadable data.

7. Save Encrypted File
The encrypted content is saved in a new file with a .enc extension (e.g., example.txt.enc).

8. Confirmation
The tool confirms that the file has been encrypted successfully and stored securely.

# Process of Decryption 

1. User Input
The user runs the tool and chooses the decryption option (D) from the menu.

2. Encrypted File Selection
The user enters the name/path of the encrypted file (e.g., example.txt.enc).

3. Password Entry
The tool asks the user to enter the same password used during encryption.

4. Key Derivation
A cryptographic key is recreated from the entered password to match the original encryption key.

5. Read Encrypted Data
The tool reads the contents of the .enc file in binary format.

6. AES-256 Decryption
The encrypted data is decrypted using the AES-256 algorithm and the derived key.

7. Save Decrypted File
The original file content is restored and saved with a .dec extension (e.g., example.txt.dec).

8. Confirmation
The tool confirms that the file has been successfully decrypted and saved.

# How the Tool Works 

1. Run the Tool

User chooses to encrypt (E) or decrypt (D).

2. File Input

User enters the file path and a password.

4. Key Generation

A secure key is created from the password.

5. Encryption or Decryption

If encrypting: the file is locked using AES-256 and saved as .enc.

If decrypting: the file is unlocked using the same password and saved as .dec.

6. End

The tool confirms success and stores the new file securely.

# OUTPUT

