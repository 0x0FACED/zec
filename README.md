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
$ ./zec new --file secrets
Enter password for file: test
6:28PM INF File successfully created file=secrets.zec
```

We can easily check header of file and secrets meta:

```sh
$ ./zec header --file secrets
Enter password: test
╭────────────────────┬─────────────────────────────────────────────────────────────────────╮
│ Field              │ Value                                                               │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Version            │ 0x01                                                                │
│ CompleteFlag       │ 7                                                                   │
│ Created At         │ Thu, 08 May 2025 18:28:11 +0300                                     │
│ Modified At        │ Thu, 08 May 2025 18:28:11 +0300                                     │
│ Secret Count       │ 0                                                                   │
│ Data Size          │ 0 bytes                                                             │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Argon Memory       │ 256.0 KiB                                                           │
│ Argon Iterations   │ 5                                                                   │
│ Argon Parallelism  │ 1                                                                   │
│ Argon Salt         │ 5496c35685f7eff72192e9ed57126376                                    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Encryption Algo    │ 1                                                                   │
│ Owner ID           │ 9b0e4e6b278241a4a762fa3b6b0fc76b                                    │
│ Verification Tag   │ 0eaacebb82e4a31956fcf75938ba2801                                    │
│ Encrypted FEK      │ 1d3fe057ec100fe6f9c1f7a4314961513341725836c043c4ddfb11186c1c0713... │
│ Checksum (SHA-256) │ c9ca20689c634a022a126d18b278c7a9ae12688e982aeb75850acc2dec300fac    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Index Table Offset │ 256                                                                 │
│ Index Table Nonce  │ 42ada8b3a1325153ab8b9193                                            │
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
- **Encryption Algo** = 1 - ChaCha20Poly1305. Other algos is not supported yet
- **Owner ID** - just UUIDv4 generated for file
- **Verification Tag** - calculated HMAC tag from master key which generated from password with argon
-  **Encrypted FEK** - encrypted file encryption key that used to encrypt all secrets
-  **Checksum (SHA-256)** - checksum of all the file expect checksum field (header + secrets + index table)
-  **Index Table Offset** = 256 - offset of index table (currenty there is not index table because of 0 secrets stored)
-  **Index Table Nonce** - nonce for encryption index table

Okay, lets add one secret:

```sh
$ ./zec add --file secrets --name mysecret --payload my_github_token
Enter password: test
writing encrypted data 100% |██████████████████████████████████████████████████████████████████████████████████████████| (31/31 B, 415 kB/s)        
6:41PM INF Secret successfully added to file file=secrets.zec secret_name=mysecret
```

Lets check index table and header after adding secret:

```sh
$ ./zec list --file secrets
Enter password: test
╭─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Secrets                                                                                                                 │
├──────────┬─────────────────────────────────┬─────────────────────────────────┬────────────────┬──────────┬──────┬───────┤
│ ID       │ Created At                      │ Modified At                     │ Offset In File │ Size     │ Type │ Flags │
├──────────┼─────────────────────────────────┼─────────────────────────────────┼────────────────┼──────────┼──────┼───────┤
│ mysecret │ Thu, 08 May 2025 18:41:01 +0300 │ Thu, 08 May 2025 18:41:01 +0300 │            256 │ 31 bytes │    1 │     0 │
╰──────────┴─────────────────────────────────┴─────────────────────────────────┴────────────────┴──────────┴──────┴───────╯

$ ./zec header --file secrets
Enter password: test
╭────────────────────┬─────────────────────────────────────────────────────────────────────╮
│ Field              │ Value                                                               │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Version            │ 0x01                                                                │
│ CompleteFlag       │ 7                                                                   │
│ Created At         │ Thu, 08 May 2025 18:28:11 +0300                                     │
│ Modified At        │ Thu, 08 May 2025 18:41:01 +0300                                     │
│ Secret Count       │ 1                                                                   │
│ Data Size          │ 31 bytes                                                            │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Argon Memory       │ 256.0 KiB                                                           │
│ Argon Iterations   │ 5                                                                   │
│ Argon Parallelism  │ 1                                                                   │
│ Argon Salt         │ 5496c35685f7eff72192e9ed57126376                                    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Encryption Algo    │ 1                                                                   │
│ Owner ID           │ 9b0e4e6b278241a4a762fa3b6b0fc76b                                    │
│ Verification Tag   │ 0eaacebb82e4a31956fcf75938ba2801                                    │
│ Encrypted FEK      │ 1d3fe057ec100fe6f9c1f7a4314961513341725836c043c4ddfb11186c1c0713... │
│ Checksum (SHA-256) │ 4eaea338fea66d2dd4890d02426c391e07802e55a3d9e34a629e31c4a80b5cc5    │
├────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Index Table Offset │ 287                                                                 │
│ Index Table Nonce  │ 42ada8b3a1325153ab8b9193                                            │
╰────────────────────┴─────────────────────────────────────────────────────────────────────╯
```

Lets get or secret:

```sh
$ ./zec get --file secrets --name mysecret
Enter password: test
6:45PM INF my_github_token

OR

$ ./zec get --file secrets --name mysecret --out ./test.txt
Enter password: test
reading encrypted secret 100% |████████████████████████████████████████████████████████████████████████████████████████| (31/31 B, 781 kB/s)        
writing plaintext 100% |███████████████████████████████████████████████████████████████████████████████████████████████| (15/15 B, 338 kB/s)        
6:45PM INF Secret exported file=secrets.zec out=./test.txt secret_name=mysecret
```

Now `test.txt` contains or secret (**my_github_token**).

Lets add file to secret file:

```sh
$ ./zec add --file secrets --name my_go.mod --payload ./go.mod
Enter password: test
writing encrypted data 100% |████████████████████████████████████████████████████████████████████████████████████████| (1.1/1.1 kB, 13 MB/s)        
6:47PM INF Secret successfully added to file file=secrets.zec secret_name=my_go.mod
```

And than extract file from secret storage:

```sh
$ ./zec get --file secrets --name my_go.mod --out ./test_gomod.txt
Enter password: test
reading encrypted secret 100% |██████████████████████████████████████████████████████████████████████████████████████| (1.1/1.1 kB, 25 MB/s)        
writing plaintext 100% |████████████████████████████████████████████████████████████████████████████████████████████| (1.0/1.0 kB, 3.3 MB/s)        
6:49PM INF Secret exported file=secrets.zec out=./test_gomod.txt secret_name=my_go.mod
```

Now we have all content of `go.mod` in `./test_gomod.txt` file!

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
// 64 bytes
type SecretMeta struct {
	ID         [16]byte // 16 bytes, secret ID (name or uuid). if name not provided - use uuid (not good)
	Offset     uint64   // 8 bytes, offset of the secret in the file
	Size       uint64   // 8 bytes, size of the secret
	CreatedAt  uint64   // 8 bytes, time of creation (unix)
	ModifiedAt uint64   // 8 bytes, time of last modification (unix)
	Type       uint8    // 1 byte, secret type (0x01 — file, 0x02 — text, 0x03 — binary for example)
	Flags      uint8    // 1 byte, bit flags (0x01 — encrypted, 0x02 — compressed, 0x04 — deleted for example)
	Nonce      [12]byte // 12 bytes, iv for encryption (chacha20 or aes-gcm)
	Reserved   [2]byte  // 2 bytes, reserved for future use (2 bytes)
}
```

You may found this struct in `pkg/core/v1/types/secret_meta.go`

## How it works

Secrets can be any data: **plain text, any files**. 

Secrets are stored encrypted with `Chacha20Poly1305`. If the secret is text, this string is converted into a byte array. A random `Nonce` is generated for the secret, which is used during encryption. The meta-information about the secret is written to the index table. The index table is stored at the very end of the file, after the secrets. 

Each file is protected by its own password, which must be specified when the file is created. The password is not stored in any form. A `Master Key` with a `salt of 16 bytes` is generated based on the password. The `key` itself is 32 bytes long. Next, a random array of bytes of size 32 is generated - this is `FEK` (**File Encryption Key**). This `FEK` is encrypted using `ChaCha20Poly1305` based on the `Master Key` with a random `Nonce`. The output is an `EncryptedFEK` of 60 bytes, where the first 12 bytes are `Nonce`, 32 bytes are `ciphertext` and 16 bytes are `auth tag`.

This key is used to encrypt secrets with a unique `Nonce` per secret. It is worth noting that the key itself is also encrypted (`EncryptedFEK`). Its decryption takes place at each step of file handling: adding a secret (`zec add`), reading a secret (`zec get`), reading meta-information about all secrets (`zec list`) and reading the header (`zec header`).

The `HMAC` tag is used to verify the user. It is calculated 1 time and is located in the `Header` of the file. When entering each command, `Master Key` is calculated from the entered password, `VerificationTag` is calculated and compared with the tag from the `header`. If the tags match, the `FEK` can be decrypted. This `FEK` is then used for all operations.

**All secret payloads and the index table are encrypted.**