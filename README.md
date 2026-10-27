# Key Distribution Scenario (KDC, Alice, Bob) dengan AES manual

Tugas 2 Keamanan Informasi. Tiga entitas (KDC, Alice, Bob) berjalan di tiga IP
berbeda, menjalankan lima langkah Key Distribution Scenario, lalu Alice dan Bob
bertukar pesan terenkripsi AES secara dua arah. Semua crypto ditulis manual,
hanya standard library Python.

## Struktur

```
keydist/
  caesar.py     Caesar cipher atas ASCII printable, sisi key jangka panjang KDC
  aes.py        AES-128/192/256 manual, mode CBC, padding PKCS#7
  protocol.py   framing JSON per baris, nonce, pembentukan Ks
  kdc.py        server KDC dan konsol admin
  node.py       Alice/Bob: initiator, responder, chat terenkripsi, REPL
tests/
  test_caesar.py
  test_aes.py
  test_protocol.py
```

Kebutuhan: Python 3.8+, tanpa dependency tambahan. Cara menjalankan, protokol,
dan filter Wireshark menyusul setelah modul lengkap.
