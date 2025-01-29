# Rainbow-table-generator
A md5, sha1, sha256, sha512 hash lookup table (sqlite) generator from a wordlist in c


## Description

This project is a piece of c code that when compiled can generate an sql database with md5, sha1, sha256, sha512 hashes and their plaintexts from a wordlist.


## Usage/Examples


For linux you should install the ssl, crypto and sqlite3 packages on debian with apt

```bash
sudo apt install libssl-dev libcrypto-dev sqlite3 -y
```



Clone the project

```bash
  git clone https://github.com/TJulesL/Rainbow-table-generator.git
```

Go to the project directory

```bash
  cd Rainbow-table-generator
```

Compile the file 

```bash
  gcc main.c -o output -lssl -lcrypto -lsqlite3
```

Execute the file
```bash
  ./output
```
