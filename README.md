# zec

     It's a training project.

**Zec (Zipped Encrypted Container)** is a container-based secret vault. All secrets are stored in files with the `*.zec` extension.

The idea is to store secrets in a compressed and encrypted form. When reading a file, only the header and index table are read.

The index table contains all the meta-information about the secrets, but not the secrets themselves. In this way, it is possible to know the contents of the file without reading the file itself.


## File structure

```
+----------------------+  <-- offset 0
|     File Header      |  (128 bytes, fixed size)
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

PREV:
```go
// 128 bytes
type Header struct {
	Version          uint8    // 1 byte — file version (0x01)
	CompleteFlag     uint8    // 1 byte — did write complete
	EncryptionAlgo   uint8    // 1 byte — ecnryption algorithm
	_                uint8    // 1 byte — just for padding
	SecretCount      uint32   // 4 bytes — secret count
	CreatedAt        int64    // 8 bytes — time of creation
	ModifiedAt       int64    // 8 bytes — time of last modification
	DataSize         uint64   // 8 bytes — size of the data (playload)
	OwnerID          [16]byte // 16 bytes —  uuid of the owner
	Nonce            [12]byte // 12 bytes — iv for encryption (chacha20 or aes-gcm)
	_                [4]byte  // 4 bytes — padding between nonce and checksum
	Checksum         [32]byte // 32 bytes — checksum of the file (sha256)
	IndexTableOffset uint64   // 8 bytes — offset of the index table
	Reserved         [24]byte // 24 bytes — for future use
}
```

CURR (added argon params):
```go
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
	Nonce            [12]byte // 12 bytes — iv for encryption (chacha20 or aes-gcm)
	ArgonSalt        [16]byte // 16 bytes — Argon2 salt
	ArgonIterations  uint16   // 2 bytes — Argon2 iterations
	ArgonParallelism uint8    // 1 byte — Argon2 parallelism
	_                uint8    // 1 byte — padding between nonce and checksum
	Checksum         [32]byte // 32 bytes — checksum of the file (sha256)
	IndexTableOffset uint64   // 8 bytes — offset of the index table
	Reserved         [8]byte  // 8 bytes — for future use
}
```

You may found this struct in `pkg/core/v1/types/header.go`