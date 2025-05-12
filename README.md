# zec

     It's a training project.

**Zec (Zipped Encrypted Container)** is a container-based secret vault. All secrets are stored in files with the `*.zec` extension.

The idea is to store secrets in a compressed and encrypted form. When reading a file, only the header and index table are read.

The index table contains all the meta-information about the secrets, but not the secrets themselves. In this way, it is possible to know the contents of the file without reading the file itself.

## Usage

```go
zec — a safe cli tool to store your secrets

Usage:
  zec [command]

Available Commands:
  add         Add secret to file
  completion  Generate the autocompletion script for the specified shell
  get         Get secret from file
  header      Show header of file
  help        Help about any command
  list        List secrets info from file
  new         Create new file with secrets

Flags:
  -h, --help   help for zec

Use "zec [command] --help" for more information about a command.
```

## Examples

Lets create new secret file:

```sh
$ ./zec new --file=test
Enter password for file: test
re-calculating HMAC 100% [====================] (1/1)
re-writing index table 100% [====================] (1/1)
re-writing header [1/2] 100% [====================] (1/1)
calculating checksum 100% [====================] (1/1)
re-writing header [2/2] 100% [====================] (1/1)
syncing file 100% [====================] (1/1)
5:51PM INF File successfully created file=test.zec
```

We can easily check header of file and secrets meta:

```sh
$ ./zec header --file test
Enter password: test
calculating checksum 100% [====================] (1/1)
╭────────────────────┬─────────────────────────────────────────────────────────────────────╮
│ Field              │ Value                                                               │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Version            │ 0x01                                                                │
│ CompleteFlag       │ 7                                                                   │
│ Created At         │ Mon, 12 May 2025 17:51:41 +0300                                     │
│ Modified At        │ Mon, 12 May 2025 17:51:41 +0300                                     │
│ Secret Count       │ 0                                                                   │
│ Data Size          │ 0 bytes                                                             │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Argon Memory       │ 256.0 KiB                                                           │
│ Argon Iterations   │ 5                                                                   │
│ Argon Parallelism  │ 1                                                                   │
│ Argon Salt         │ 6f20c6752b981c3e140e75a60a037eec                                    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Encryption Algo    │ 1                                                                   │
│ Owner ID           │ 30326815beae46948891472d3ec4989b                                    │
│ Verification Tag   │ caad66ad6dd3a5d8d653281b50d8f06b                                    │
│ Encrypted FEK      │ 687341c0485a88ddbebbfb2d2fbbddefc90beec773cf14bc10a4eaa2bbb6b2d7... │
│ Checksum (SHA-256) │ 48aaac4b5b491a96c75f9146f10e0a96da2bb30d74572a6277ab6b181a243bb1    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Index Table Offset │ 256                                                                 │
│ Index Table Nonce  │ 9340bb3d5dfce4bc86732c04                                            │
╰────────────────────┴─────────────────────────────────────────────────────────────────────╯
```

- **Version** = 1 - version of zec that created this file
- **Complete Flag** = 7 - `1 | 2 | 4` - Completed, Encrypted, Compressed (incorrect, not encrypted and compressed yet)
*P.S. You may found flags int `pkg/core/v1/types/flags.go`*
- **Created At** - time of file creation
- **Modified At** - time of file modification (add new secret for now)
- **Secret Count** = 0 - number of secrets
- **Data Size** = 0 - summary size of all secrets
- **Argon Memory** = 256 KiB which is 2^18 bytes. How much memory used in `Argon2id`
- **Argon Iterations** = 5 - number of argon iterations
- **Argon Parallelism** = 1 - how much threads will be used
- **Argon Salt** - generated salt for argon
- **Encryption Algo** = 1 - ChaCha20Poly1305. Other algos is not supported yet. This will be removed, because secrets can be encrypted with any algorithm (xchacha20, chacha20. aes in the future)
- **Owner ID** - just UUIDv4 generated for file
- **Verification Tag** - calculated HMAC tag from master key which generated from password with argon
-  **Encrypted FEK** - encrypted file encryption key that used to encrypt all secrets
-  **Checksum (SHA-256)** - checksum of all the file expect checksum field (header + secrets + index table)
-  **Index Table Offset** = 256 - offset of index table (currenty there is not index table because of 0 secrets stored)
-  **Index Table Nonce** - nonce for encryption index table

Okay, lets add two secrets. First - plain text, Second - large 900mb video file:

```sh
$ ./zec add --file test --name secret1 --payload my_ssh
Enter password: test
calculating checksum 100% [====================] (1/1)
writing encrypted data 100% [==============================] (22/22 B, 352 kB/s) 
re-calculating HMAC 100% [====================] (1/1)
re-writing index table 100% [====================] (1/1)
re-writing header [1/2] 100% [====================] (1/1)
calculating checksum 100% [====================] (1/1)
re-writing header [2/2] 100% [====================] (1/1)
syncing file 100% [====================] (1/1)
5:55PM INF Secret successfully added to file file=test.zec secret_name=secret1

$ ./zec add --file test --name secret_video_900mb --payload "/path/to/large.mp4"
Enter password: test
calculating checksum 100% [====================] (1/1)
encrypting data 100% [==============================] (983/983 MB, 284 MB/s) 
re-calculating HMAC 100% [====================] (1/1)
re-writing index table 100% [====================] (1/1)
re-writing header [1/2] 100% [====================] (1/1)
calculating checksum 100% [====================] (1/1)
re-writing header [2/2] 100% [====================] (1/1)
syncing file 100% [====================] (1/1)
5:58PM INF Secret successfully added to file file=test.zec secret_name=secret_video_900mb
```

Lets check index table and header after adding secrets:

```sh
$ ./zec list --file test
Enter password: test
calculating checksum 100% [====================] (1/1)
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Secrets                                                                                                                                          │
├────────────────────┬─────────────────────────────────┬─────────────────────────────────┬────────────────┬──────────┬──────┬──────────────┬───────┤
│ Name               │ Created At                      │ Modified At                     │ Offset In File │ Size     │ Type │ Encrypt Mode │ Flags │
├────────────────────┼─────────────────────────────────┼─────────────────────────────────┼────────────────┼──────────┼──────┼──────────────┼───────┤
│ secret1            │ Mon, 12 May 2025 17:55:56 +0300 │ Mon, 12 May 2025 17:55:56 +0300 │            256 │ 22 bytes │ Text │ AEAD         │     0 │
│ secret_video_900mb │ Mon, 12 May 2025 17:58:43 +0300 │ Mon, 12 May 2025 17:58:43 +0300 │            278 │ 0.9 GiB  │ File │ Streaming    │     1 │
╰────────────────────┴─────────────────────────────────┴─────────────────────────────────┴────────────────┴──────────┴──────┴──────────────┴───────╯

$ ./zec header --file test
Enter password: test
calculating checksum 100% [====================] (1/1)
╭────────────────────┬─────────────────────────────────────────────────────────────────────╮
│ Field              │ Value                                                               │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Version            │ 0x01                                                                │
│ CompleteFlag       │ 7                                                                   │
│ Created At         │ Mon, 12 May 2025 17:51:41 +0300                                     │
│ Modified At        │ Mon, 12 May 2025 17:58:43 +0300                                     │
│ Secret Count       │ 2                                                                   │
│ Data Size          │ 0.9 GiB                                                             │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Argon Memory       │ 256.0 KiB                                                           │
│ Argon Iterations   │ 5                                                                   │
│ Argon Parallelism  │ 1                                                                   │
│ Argon Salt         │ 6f20c6752b981c3e140e75a60a037eec                                    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Encryption Algo    │ 1                                                                   │
│ Owner ID           │ 30326815beae46948891472d3ec4989b                                    │
│ Verification Tag   │ a215592b0519ff0e979b16f3680fb2a0                                    │
│ Encrypted FEK      │ 687341c0485a88ddbebbfb2d2fbbddefc90beec773cf14bc10a4eaa2bbb6b2d7... │
│ Checksum (SHA-256) │ 34b613481f8a8f6d99740d85fd103617b00f90474ef1af054978884ebeaaa292    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Index Table Offset │ 983380018                                                           │
│ Index Table Nonce  │ 9340bb3d5dfce4bc86732c04                                            │
╰────────────────────┴─────────────────────────────────────────────────────────────────────╯
```

Lets print text secret:

```sh
$ ./zec get --file test --name secret1
Enter password: test
calculating checksum 100% [====================] (1/1)
converting name to bytes 100% [====================] (1/1)
decrypting FEK 100% [====================] (1/1)
reading secret 100% [==============================] (22/22 B, 1.3 MB/s) 
decrypting data 100% [====================] (1/1)
6:03PM INF my_ssh

// or you can use flag --out to save secret to file to provided path

$ ./zec get --file test --name secret_video_900mb --out ./test.mp4
Enter password: test
calculating checksum 100% [====================] (1/1)
converting name to bytes 100% [====================] (1/1)
decrypting FEK 100% [====================] (1/1)
decrypting data 100% [==============================] (983/983 MB, 185 MB/s) 
6:04PM INF Secret exported file=test.zec out=./test.mp4 secret_name=secret_video_900mb
```

Now `test.mp4` is our `/path/to/large.mp4`.

## File structure

```
+----------------------+  <-- offset 0
|     File Header      |  (256 bytes, fixed size)
+----------------------+
+----------------------+  <-- offset = 0 + 128
|  EncryptedSecret #1  |  (for example, 1024 bytes)
+----------------------+
+----------------------+  <-- offest = 128 + 1024
|  EncryptedSecret #2  |  (for example, 512 bytes)
+----------------------+
     ... more secrets ...
+------------------------------+  <-- offset X (after last secret)
|          Index Table         |
| [SecretRecord #1]            |
| [SecretRecord #2]            |
|    ... up to SecretCount     |
+------------------------------+
```

### File header 

File header contains next fields:

```go
// 256 bytes
type Header struct {
	Version          uint8    // 1 byte — file version (0x01)
	CompleteFlag     uint8    // 1 byte — did write complete
	EncryptionAlgo   uint8    // 1 byte — ecnryption algorithm
	ArgonMemoryLog2  uint8    // 1 byte — log2(memory in KB) for Argon2
	SecretCount      uint32   // 4 bytes — secret count
	CreatedAt        int64    // 8 bytes — time of creation
	ModifiedAt       int64    // 8 bytes — time of last modification
	DataSize         uint64   // 8 bytes — size of the data (playload)
	OwnerID          [16]byte // 16 bytes —  uuid of the owner
	ArgonSalt        [16]byte // 16 bytes — Argon2 salt
	ArgonIterations  uint16   // 2 bytes — Argon2 iterations
	ArgonParallelism uint8    // 1 byte — Argon2 parallelism
	_                uint8    // 1 byte — padding between nonce and checksum
	Checksum         [32]byte // 32 bytes — checksum of the file (sha256)
	VerificationTag  [16]byte // 16 bytes — HMAC(master_key, "zec-verification")[:16]
	EncryptedFEK     [60]byte // 60 bytes — nonce (12) + ciphertext (32) + tag (16)
	IndexTableOffset uint64   // 8 bytes — offset of the index table
	IndexTableNonce  [12]byte // 12 bytes — nonce for enc index table
	Reserved         [60]byte // 60 bytes — for future use
}
```

You may found this struct in `pkg/core/v1/types/header.go`

## Secret Meta

Secret meta contains the next fields:

```go
// fixed size secret metadata structure
// 94 bytes
type SecretMeta struct {
	// UUID is not used. flag --name is required
	Name        [32]byte // 32 bytes, secret ID (name or uuid). if name not provided - use uuid (not good)
	Offset      uint64   // 8 bytes, offset of the secret in the file
	Size        uint64   // 8 bytes, size of the secret
	CreatedAt   uint64   // 8 bytes, time of creation (unix)
	ModifiedAt  uint64   // 8 bytes, time of last modification (unix)
	Type        uint8    // 1 byte, secret type (0x01 — file, 0x02 — text, 0x03 — binary for example)
	Flags       uint8    // 1 byte, bit flags (0x01 — encrypted, 0x02 — compressed, 0x04 — deleted for example)
	_           [1]byte  // padding
	Nonce       [24]byte // 24 bytes, iv for encryption (chacha20[:12] xchacha20[:],  or aes-gcm[:12])
	EncryptMode uint8    // 1 byte, AEAD or Streaming chacha20
}
```

You may found this struct in `pkg/core/v1/types/secret_meta.go`

## How it works

	TODO: update

Secrets can be any data: **plain text, any files**. 

Secrets are stored encrypted with `Chacha20Poly1305`. If the secret is text, this string is converted into a byte array. A random `Nonce` is generated for the secret, which is used during encryption. The meta-information about the secret is written to the index table. The index table is stored at the very end of the file, after the secrets. 

Each file is protected by its own password, which must be specified when the file is created. The password is not stored in any form. A `Master Key` with a `salt of 16 bytes` is generated based on the password. The `key` itself is 32 bytes long. Next, a random array of bytes of size 32 is generated - this is `FEK` (**File Encryption Key**). This `FEK` is encrypted using `ChaCha20Poly1305` based on the `Master Key` with a random `Nonce`. The output is an `EncryptedFEK` of 60 bytes, where the first 12 bytes are `Nonce`, 32 bytes are `ciphertext` and 16 bytes are `auth tag`.

This key is used to encrypt secrets with a unique `Nonce` per secret. It is worth noting that the key itself is also encrypted (`EncryptedFEK`). Its decryption takes place at each step of file handling: adding a secret (`zec add`), reading a secret (`zec get`), reading meta-information about all secrets (`zec list`) and reading the header (`zec header`).

The `HMAC` tag is used to verify the user. It is calculated 1 time and is located in the `Header` of the file. When entering each command, `Master Key` is calculated from the entered password, `VerificationTag` is calculated and compared with the tag from the `header`. If the tags match, the `FEK` can be decrypted. This `FEK` is then used for all operations.

**All secret payloads and the index table are encrypted.**