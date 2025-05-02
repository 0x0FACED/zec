# zec

test secret vault

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
+----------------------+
|   IndexTableOffset   |  (8 bytes, uint64: points to Index Table start)
+----------------------+
```