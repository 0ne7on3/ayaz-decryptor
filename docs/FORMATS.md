# Input formats

All values and paths in the example are synthetic. A profile belongs to one
group of encrypted files; there is no universal key or built-in victim key.

## JSON profile

| Field | Meaning |
| --- | --- |
| `key_blob_sha256` | SHA-256 of the encrypted file's final 128 bytes, as 64 hexadecimal characters. |
| `stream_hex` | Known metadata keystream bytes in hexadecimal. |
| `known_mask_hex` | One `01` byte for each known keystream position and `00` for each unknown position. |

The keystream and mask must have equal lengths and cover the target file's
metadata. Unknown keystream bytes are usually zero-filled, but a zero value
alone does not mean a byte is known. The CLI accepts JSON files up to 2 MiB.

`stream_hex` is XORed with the metadata. The complete **64-byte Salsa20 state**
is stored inside the decrypted metadata and is used for file content. These are
different values. The `encrypted XOR original` stream from one file pair's
content cannot replace the metadata profile.

## Footer and encryption layout

Numbers use little-endian encoding. The file ends with:

```text
content | encrypted metadata [N bytes] | N [uint16] | checksum [uint32] | key_blob [128 bytes]
```

The final 134 bytes have a fixed size. Supported `N` values range from 83 to
8192 bytes. The group is identified by the exact SHA-256 of `key_blob`; this
project does not perform RSA decryption or validate its checksum. In the
synthetic example, `key_blob` contains test bytes and the checksum is zero.

After the XOR step, the metadata contains:

| Field | Size |
| --- | --- |
| Null-terminated original filename in UTF-16LE, compressed with aPLib | `N - 82` bytes |
| Compressed filename length | `uint16` |
| Length of an unencrypted content span | `uint64` |
| `before` | `uint32` |
| `after` | `uint32` |
| Salsa20/20 state for the content | 64 bytes |

First, `before + 1` blocks of 128 KiB are processed, followed by an unencrypted
span. Then `after + 1` encrypted blocks and an unencrypted span repeat. The last
block is limited by the remaining content length. The Salsa20 counter continues
across encrypted spans; skipped spans do not advance it. The skipped span must
be at least 128 KiB and a multiple of 128 KiB. Both `before` and `after` range
from 0 to 4095.

Normal mode requires every metadata byte and a matching original filename.
`--allow-unknown-name` permits unknown compressed filename bytes when the final
82 bytes are fully known; known filenames are still checked. Without
`--expected-sha256`, content integrity is not independently verified.

## ZIP archive of known file pairs

The archive root must contain `manifest.json` with this structure. Hashes in the
example are placeholders and must be replaced with actual 64-character SHA-256
values:

```json
{
  "pair_count": 1,
  "pairs": [{
    "inode": 1,
    "category": "synthetic",
    "validation": "synthetic_fixture",
    "encrypted": {
      "archive_path": "encrypted/encrypted.bin",
      "size": 256,
      "sha256": "SHA256_OF_ENCRYPTED_BYTES"
    },
    "decrypted": {
      "archive_path": "decrypted/a.txt",
      "original_name": "a.txt",
      "size": 28,
      "sha256": "SHA256_OF_ORIGINAL_BYTES"
    }
  }]
}
```

`pair_count` must match the length of the nonempty `pairs` list. Both sides need
`archive_path`, the exact `size`, and the SHA-256 of the entire member. `verify`
also needs `decrypted.original_name`. The optional `inode` is an entry identifier;
it need not be an actual filesystem inode. `category` and `validation` are
optional. `original_name` is allowed on the encrypted side but is not used.

Paths must be unique and relative, with no `..`, backslashes, or null bytes.
Symlinks, special files, duplicate names or JSON keys, and password-protected
archives are rejected. ZIP members are read without extraction. Limits are
2,000 members, 64 MiB per member, 128 MiB total, and 2 MiB for the manifest.

`analyze` validates the archive and extracts partial keystream coverage from the
compressed filename length field; it does not automatically produce a complete
profile. `verify` compares decrypted content with the supplied originals. A
match confirms these pairs, but does not prove that the source archive is genuine.

For a working example, run `python examples/make_demo.py demo-output` after
installing the package. It creates a new directory and never overwrites one.
