# RFS-Prototype

RfS Console Prototype

## Security

**Hashing**: Passwords are hashed through __100k__ rounds of sha256, and salted with a cryptographically-secure salt of 32 characters.

**Encryption**: Data is encrypted through AES-256.

## GUI

The GUI will be written using wxWidgets.

## Functionalities

Users are able to:

 - *Store, delete and export* files and folders 🔒📁
 - *Display all files* in current directory 🔎
 - *Move* into and out of folders ➡️
 - *Open files* (read only) 📝
 - *Change their password* 🔑
