# Key Distribution Scenario (KDC, Alice, Bob) dengan AES manual

Tugas 2 Keamanan Informasi. Tiga entitas (KDC, Alice, Bob) berjalan di tiga IP berbeda,
menjalankan lima langkah Key Distribution Scenario, lalu Alice dan Bob bertukar pesan
terenkripsi AES secara dua arah. Enkripsi di sisi KDC memakai Caesar cipher sederhana,
AES dipakai untuk autentikasi (langkah 4-5) dan komunikasi. Semua ditulis manual,
hanya standard library Python, tanpa dependency tambahan.

## Struktur proyek

```
keydist/
  __init__.py
  aes.py        AES-128/192/256 manual, mode CBC, padding PKCS#7, CLI bantu
  caesar.py     Caesar cipher atas ASCII printable (32..126), key integer mod 95, output hex
  protocol.py   framing JSON per baris, nonce 32-bit, session key 16 karakter, pack/unpack
  kdc.py        server KDC (threaded TCP) + konsol admin
  node.py       Alice/Bob: initiator, responder, chat dua arah terenkripsi AES, REPL
tests/
  test_aes.py        vektor FIPS-197 (Appendix B, C) dan NIST SP 800-38A, padding, key
  test_caesar.py     geseran, wrap, key invalid, data invalid
  test_protocol.py   lima langkah end-to-end, dua arah, key salah, replay, tampering
```

Kebutuhan: Python 3.8+, jalankan semua perintah dari folder proyek ini.

## Sintaks lengkap

### 1. KDC

```
python -m keydist.kdc [--host ADDRESS] [--port PORT] [--key ID=SHIFT ...]
```

| Opsi | Default | Arti |
|------|---------|------|
| `--host` | `0.0.0.0` | alamat yang di-bind (0.0.0.0 = semua interface) |
| `--port` | `5000` | port TCP layanan |
| `--key ID=SHIFT` | kosong | daftar identitas saat start, boleh diulang |

Perintah KDC di konsol (`kdc>`):

| Perintah | Contoh | Fungsi |
|----------|--------|--------|
| `setkey <id> <shift>` | `setkey alice 7` | daftar / ganti key jangka panjang sebuah identitas |
| `delkey <id>` | `delkey bob` | hapus identitas |
| `keys` | | daftar identitas, key ditandai `*` |
| `keys show` | | daftar identitas dengan key terlihat |
| `help` | | cetak bantuan |
| `quit` / `exit` / Ctrl+C | | matikan server |

Ctrl+D (stdin tertutup) membuat KDC tetap jalan tanpa konsol. Satu koneksi = satu
permintaan kunci; node membuka koneksi baru ke KDC tiap `connect`. Permintaan yang
tidak lengkap dalam 10 detik diputus.

Key Caesar: bilangan bulat apa pun kecuali kelipatan 95 (0, 95, 190 ditolak);
yang dipakai adalah `shift mod 95`, jadi `7` dan `102` setara.

Contoh:

```
python -m keydist.kdc --host 0.0.0.0 --port 5000
python -m keydist.kdc --key alice=7 --key bob=13
```

### 2. Node (Alice / Bob)

```
python -m keydist.node --name ID [--key SHIFT] [--kdc HOST:PORT]
                       [--listen-host ADDRESS] [--listen-port PORT]
```

| Opsi | Default | Arti |
|------|---------|------|
| `--name` | wajib | identitas, 1-16 karakter `A-Z a-z 0-9 _ -` |
| `--key` | ditanya saat start | key Caesar (integer), harus sama dengan di KDC |
| `--kdc` | `127.0.0.1:5000` | alamat KDC `host:port` |
| `--listen-host` | `0.0.0.0` | alamat bind untuk menerima koneksi peer |
| `--listen-port` | `6001` | port dengar; pakai 6002 untuk Bob |

Saat start node mencetak IP lokal yang dipakai menuju KDC — berguna untuk memilih
interface yang benar di Wireshark.

Perintah REPL (`nama>`):

| Perintah | Contoh | Fungsi |
|----------|--------|--------|
| `connect <peer> <host>:<port>` | `connect bob 192.168.1.12:6002` | jalankan langkah 1-5; `Ks` baru setiap kali dipanggil (rekey) |
| `send <peer> <pesan>` | `send bob Halo Bob` | kirim pesan ASCII terenkripsi AES-CBC dengan `Ks` |
| `sessions` | | daftar sesi aktif beserta `Ks` |
| `close <peer>` | `close bob` | kirim BYE dan tutup sesi |
| `key` | | tampilkan key Caesar sendiri |
| `setkey <shift>` | `setkey 21` | ganti key tanpa restart (harus diikuti `setkey <id> <shift>` di KDC) |
| `kdc <host>:<port>` | `kdc 192.168.1.10:5000` | ganti alamat KDC |
| `help` | | daftar perintah |
| `quit` / `exit` / Ctrl+C | | tutup semua sesi dan keluar |

Kesalahan usage dicetak jelas, misalnya `usage: connect <peer> <host>:<port>`.

### 3. AES sebagai alat bantu baris perintah

```
python -m keydist.aes enc KEY TEXT [IV_HEX]
python -m keydist.aes dec KEY CIPHER_HEX
```

- `KEY` harus ASCII; 1-16 karakter dipakai sebagai AES-128, 17-24 AES-192, 25-32 AES-256
  (kurang dari batas bawah diisi byte nol; lebih dari 32 karakter ditolak).
- `IV_HEX` opsional, 32 digit hex. Tanpa `IV_HEX`, IV acak per enkripsi.
- Ciphertext = hex dari `IV (16 byte) || blok-blok CBC`, jadi `dec` hanya butuh
  key dan satu string hex (IV sudah ada di depan).

Contoh (bolak-balik cocok):

```
python -m keydist.aes enc "KunciAES1234567" "Halo" 000102030405060708090a0b0c0d0e0f
python -m keydist.aes dec "KunciAES1234567" <hex_dari_output_di_atas>
```

Cocokkan dengan OpenSSL bila diminta:

```
openssl enc -aes-128-cbc -K <hex_key_32_digit> -iv 000102030405060708090a0b0c0d0e0f \
        -in halo.txt -out halo.bin | xxd -p
```

### 4. Pemakaian sebagai modul

```python
from keydist.aes import prepare_key, encrypt_text, decrypt_text
from keydist import caesar

k = prepare_key("KunciAES1234567")          # ASCII -> 16/24/32 byte
c = encrypt_text(k, "Halo")                 # hex, IV acak di depan
assert decrypt_text(k, c) == "Halo"

h = caesar.encrypt(7, "abc||Ks")            # hex, karakter 32..126 saja
assert caesar.decrypt(7, h) == "abc||Ks"
```

## Menjalankan di tiga perangkat

Contoh IP: KDC `192.168.1.10`, Alice `192.168.1.11`, Bob `192.168.1.12` (satu jaringan,
mis. Wi-Fi kampus atau hotspot HP). Buka firewall untuk port 5000, 6001, 6002 di tiap
mesin (Windows: izinkan Python lewat firewall saat dialog pertama muncul).

Perangkat KDC:

```
python -m keydist.kdc --host 0.0.0.0 --port 5000
kdc> setkey alice 7
kdc> setkey bob 13
```

Perangkat Alice:

```
python -m keydist.node --name alice --kdc 192.168.1.10:5000 --listen-port 6001
Caesar key, integer (same as at KDC): 7
alice> connect bob 192.168.1.12:6002
alice> send bob Halo Bob
```

Perangkat Bob:

```
python -m keydist.node --name bob --kdc 192.168.1.10:5000 --listen-port 6002
Caesar key, integer (same as at KDC): 13
bob> send alice Halo Alice
```

Setelah `connect` selesai, koneksi TCP yang sama dipakai dua arah, jadi Bob bisa
langsung `send alice ...` tanpa `connect` sendiri. Bob juga bisa menjadi initiator:

```
bob> connect alice 192.168.1.11:6001
```

### Satu perangkat, tiga IP (uji lokal)

Semua alamat 127.0.0.0/8 adalah loopback, jadi di Windows/Linux cukup:

```
python -m keydist.kdc  --host 127.0.0.1 --port 5000
python -m keydist.node --name alice --kdc 127.0.0.1:5000 --listen-host 127.0.0.2 --listen-port 6001
python -m keydist.node --name bob   --kdc 127.0.0.1:5000 --listen-host 127.0.0.3 --listen-port 6002
alice> connect bob 127.0.0.3:6002
```

Di macOS perlu `sudo ifconfig lo0 alias 127.0.0.2` dan `... 127.0.0.3` sekali dulu.
Demo asli tetap memakai tiga perangkat/VM sungguhan.

## Protokol

Satu pesan = satu baris JSON berakhiran newline, sehingga terbaca utuh di Wireshark.
Semua ciphertext berupa hex. Pemisah field di dalam plaintext terenkripsi adalah `||`.

| # | Pesan JSON | Arah | Isi sebelum enkripsi | Enkripsi |
|---|------------|------|----------------------|----------|
| 1 | `{"step":1,"type":"KEY_REQUEST","id_a":...,"id_b":...,"n1":...}` | A -> KDC | - | tidak |
| 2 | `{"step":2,"type":"KEY_RESPONSE","enc_a":...,"ticket":...}` | KDC -> A | `enc_a = E(Ka,[Ks||IDA||IDB||N1])`, `ticket = E(Kb,[Ks||IDA])` | Caesar |
| 3 | `{"step":3,"type":"TICKET","ticket":...}` | A -> B | sama dengan ticket langkah 2 | Caesar |
| 4 | `{"step":4,"type":"CHALLENGE","enc_n2":...}` | B -> A | `E(Ks, N2)`, N2 acak 32-bit | AES-CBC |
| 5 | `{"step":5,"type":"RESPONSE","enc_fn2":...}` | A -> B | `E(Ks, f(N2))`, `f(N2) = N2+1` | AES-CBC |
| - | `{"type":"HANDSHAKE_OK"}` | B -> A | kontrol (ack langkah 5) | tidak |
| - | `{"type":"ERROR","reason":...}` | dua arah | kontrol (penolakan/gagal) | tidak |
| data | `{"type":"MSG","from":...,"cipher":...}` | dua arah | `E(Ks, pesan)` | AES-CBC |
| tutup | `{"type":"BYE"}` | dua arah | - | tidak |

Aturan format: key dan plaintext ASCII (non-ASCII ditolak dengan pesan jelas),
ciphertext hex (`IV 16 byte` di depan untuk AES-CBC), ID `[A-Za-z0-9_-]{1,16}`,
`Ks` = 16 karakter alfanumerik acak dari `secrets` (CSPRNG), satu baris maksimum 64 KB,
timeout handshake 10 detik.

Pemeriksaan keamanan yang diimplementasi:

- Alice memverifikasi `IDA`, `IDB`, `N1` hasil dekripsi `enc_a` (balasan KDC harus
  untuk permintaannya sendiri; menolak balasan lama / tujuan diganti).
- Bob memverifikasi isi ticket (`Ks` valid 16 alfanumerik, ID valid) dan menuntut
  langkah 5 berisi `f(N2)=N2+1` terenkripsi `Ks`, sehingga ticket yang diputar ulang
  tanpa `Ks` gagal.
- Caesar tidak bisa mendeteksi key salah, jadi isi hasil dekripsi diperiksa; jika
  `Ka`/`Kb` tidak cocok, `connect` gagal dengan pesan yang menyebut sisi mana.
- KDC menolak identitas tidak dikenal, ID tidak valid, nonce non-angka, `id_a == id_b`.

## Caesar cipher (sisi KDC)

- Key jangka panjang `Ka` dan `Kb` adalah bilangan bulat (geseran), dibagi dengan KDC
  lewat `setkey` di dua sisi.
- Alfabet: 95 karakter ASCII printable (kode 32..126). Tiap karakter digeser
  `key mod 95`, lalu hasil di-encode ASCII dan ditampilkan/dikirim sebagai hex.
  Dekripsi menggeser balik.
- Jujur soal trade-off: hanya 94 key mungkin, bisa di-brute-force seketika. Dipakai
  karena asisten membebaskan crypto sisi KDC dan mudah dijelaskan; pengganti nyata
  adalah AES untuk `E(Ka)`/`E(Kb)` (modul `aes.py` sudah mendukungnya).

## AES (autentikasi dan komunikasi)

- Implementasi sendiri dari nol: aritmetika GF(2^8) (`xtime`), S-box dibangkitkan dari
  invers perkalian + transformasi affine, key expansion 128/192/256, empat transformasi
  (SubBytes, ShiftRows, MixColumns, AddRoundKey) dan inversnya untuk dekripsi,
  jumlah round 10/12/14 (`len(key)//4 + 6`).
- Dipakai pada langkah 4, 5, dan seluruh `MSG` dengan key `Ks` (AES-128).
- Mode CBC dengan IV acak per pesan (bukan ECB: ECB membocorkan pola), padding PKCS#7
  (selalu menambah blok penuh bila perlu).
- Verifikasi ke benar: vektor resmi FIPS-197 Appendix B dan C, NIST SP 800-38A CBC.

## Wireshark

1. Pilih interface yang dipakai (Wi-Fi/Ethernet perangkat). Bila semua proses di satu
   mesin, pilih loopback (Windows: `Adapter for loopback traffic capture`;
   Linux: `lo`). Pesan `my IP towards KDC` di node menunjukkan interface yang benar.
2. Filter utama: `tcp.port == 5000 || tcp.port == 6001 || tcp.port == 6002`
3. Filter per langkah: `tcp contains "KEY_REQUEST"`, `tcp contains "KEY_RESPONSE"`,
   `tcp contains "TICKET"`, `tcp contains "CHALLENGE"`, `tcp contains "RESPONSE"`,
   `tcp contains "MSG"`.
4. Klik kanan paket -> Follow -> TCP Stream: satu stream A<->KDC (langkah 1-2),
   satu stream A<->B (langkah 3-5 lalu MSG dua arah).
5. Yang terlihat: langkah 1 dan pesan kontrol plaintext terbaca; semua payload
   terenkripsi hanya hex. `Ka`, `Kb`, dan `Ks` tidak pernah lewat jaringan sebagai
   plaintext (kecuali di log terminal masing-masing).

## Pengujian

```
python -m unittest discover -s tests -v      # seluruh suite: 32 test, harus OK
python -m unittest tests.test_aes -v         # AES saja (vektor FIPS-197, SP 800-38A)
python -m unittest tests.test_caesar         # Caesar saja
python -m unittest tests.test_protocol -v    # end-to-end 5 langkah di loopback
```

## Skenario demo (ubah key, key salah, dua arah, rekey)

1. `bob> setkey 21` lalu `kdc> setkey bob 21`; `alice> connect bob ...` lagi -> sukses,
   `Ks` baru (rekey per connect, lihat `sessions`).
2. Key tidak cocok di satu sisi saja (`bob> setkey 99`, KDC tetap 21) -> `connect`
   gagal dengan pesan yang menunjuk ticket/Kb.
3. `bob> connect alice <IP_ALICE>:6001` -> Bob initiator, lalu kirim dua arah.
4. Salah ketik `--key` saat start Alice -> langkah 2 gagal didekripsi, program
   menjelaskan `Ka` tidak cocok, tidak crash.

## Keterbatasan yang diketahui

- Hanya IPv4; plaintext dan key harus ASCII.
- Key AES pendek diisi byte nol (bukan KDF) — kemudahan demo, bukan praktik produksi.
- Tidak ada MAC; integritas hanya terdeteksi lewat padding. Bukan untuk produksi.
- Caesar sisi KDC lemah secara kriptografis (94 key) — disengaja, sesuai izin asisten.
- Skenario Stallings/Needham-Schroeder klasik: ticket lama bisa di-replay jika `Ks`
  lama bocor; KDC single point of failure; tidak ada lifetime `Ks`.
