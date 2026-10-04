# Sources and attribution

The metadata format and keystream reuse recovery method were researched by
[Calif](https://calif.io/research/lockbit-v3) and
[yohanes/lockbit-v3-linux-decryptor](https://github.com/yohanes/lockbit-v3-linux-decryptor).
Development also used the implementation description in commit
`062421d89c048fc2493002e03fa0cb7fba4d6c3f`.

This project provides a portable implementation based on published research.
It does not include the `frank` source or binaries, the `aplib.a` library, or
other files from that repository. This project's MIT license does not cover
third-party works.

Salsa20 was designed by Daniel J. Bernstein. The cryptographic tests use a
published ECRYPT vector; its source is linked beside the vector.
