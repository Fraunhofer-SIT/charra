# How to install the CHARRA man pages

- Convert the markdown files into roff

```bash
pandoc -s -t man man/verifier.1.md -o man/verifier.1
pandoc -s -t man man/attester.1.md -o man/attester.1
```

- Copy the man page to the corresponding directory

```bash
sudo cp man/attester.1 /usr/local/share/man/man1
sudo cp man/verifier.1 /usr/local/share/man/man1
```

- Update the man database

```bash
sudo mandb
```
