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

Kebutuhan: Python 3.8+, tanpa dependency tambahan. Cara menjalankan dan filter
Wireshark ditulis di bagian sendiri setelah semua modul masuk.

## Protokol

Setiap pesan adalah satu baris JSON berakhiran newline sehingga mudah dibaca di
Wireshark. Semua ciphertext berupa hex. Langkah 2 dan 3 (`E(Ka,...)`, `E(Kb,...)`)
memakai Caesar cipher; langkah 4, 5 dan `MSG` memakai AES-CBC dengan `Ks`
(16 byte pertama adalah IV). Pemisah field di dalam plaintext terenkripsi adalah `||`.

| Langkah | Arah | Isi |
|---------|------|-----|
| 1 | A → KDC | `ID_A \|\| ID_B \|\| N1` (`KEY_REQUEST`, plaintext) |
| 2 | KDC → A | `E(Ka,[Ks \|\| ID_A \|\| ID_B \|\| N1])` dan `E(Kb,[Ks \|\| ID_A])` (`KEY_RESPONSE`) |
| 3 | A → B | `E(Kb,[Ks \|\| ID_A])` (`TICKET`) |
| 4 | B → A | `E(Ks,N2)` (`CHALLENGE`) |
| 5 | A → B | `E(Ks,f(N2))`, dengan `f(N2)=N2+1` (`RESPONSE`) |
| - | B → A | `HANDSHAKE_OK` (kontrol, agar Alice tahu langkah 5 diterima) |
| setelah | A ↔ B | `MSG` berisi `E(Ks, pesan)` |

Pemeriksaan keamanan: Alice memverifikasi `ID_A`, `ID_B`, dan `N1` hasil dekripsi
balasan KDC; Bob menuntut jawaban langkah 5 sama dengan `f(N2)=N2+1` terenkripsi
`Ks`, sehingga ticket lama yang diputar ulang tanpa `Ks` ditolak. Karena Caesar
tidak bisa mendeteksi key salah, penerima juga memeriksa bentuk isi hasil dekripsi
(`Ks` 16 karakter alfanumerik, ID valid). KDC menolak identitas tidak dikenal,
ID tidak valid, nonce non-angka, dan `id_a == id_b`.

## Caesar cipher (sisi KDC)

- Key jangka panjang Ka dan Kb adalah bilangan bulat (geseran), dibagi dengan KDC
  lewat `setkey` di dua sisi.
- Alfabet: 95 karakter ASCII printable (kode 32 sampai 126). Tiap karakter digeser
  `key mod 95`; key kelipatan 95 ditolak. Hasil di-encode ASCII dan dikirim sebagai hex.
- Jujur soal trade-off: hanya 94 key mungkin, bisa di-brute-force seketika. Dipakai
  karena asisten membebaskan crypto sisi KDC dan mudah dijelaskan; pengganti nyata
  adalah AES untuk `E(Ka)`/`E(Kb)` (modul `aes.py` sudah mendukungnya).

## AES (autentikasi dan komunikasi)

- Implementasi sendiri dari nol: aritmetika GF(2^8) (`xtime`), S-box dibangkitkan
  dari invers perkalian dan transformasi affine, key expansion, SubBytes, ShiftRows,
  MixColumns, AddRoundKey dan inversnya untuk dekripsi. Round 10/12/14 untuk
  key 16/24/32 byte (`len(key)//4 + 6`).
- Key AES yang dipakai alur utama adalah `Ks` buatan KDC: 16 karakter alfanumerik
  acak dari `secrets` (CSPRNG), jadi AES-128. Key dan plaintext harus ASCII
  (non-ASCII ditolak dengan pesan jelas), ciphertext ditampilkan sebagai hex.
- Mode CBC dengan IV acak per pesan (ECB dibuang karena membocorkan pola) dan
  padding PKCS#7; selalu ada padding walau blok penuh.
- Diverifikasi dengan vektor resmi FIPS-197 Appendix B dan C serta NIST SP 800-38A.

Alat bantu baris perintah untuk mencocokkan hasil dengan sumber lain
(`dec` tidak butuh IV terpisah karena IV menempel di depan ciphertext):

```
python -m keydist.aes enc "KunciAES1234567" "Halo" 000102030405060708090a0b0c0d0e0f
python -m keydist.aes dec "KunciAES1234567" <hex>
```
