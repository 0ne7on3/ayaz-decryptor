# Search for an incomplete Salsa20 state with CUDA

This optional utility searches unknown bytes of a **complete 64-byte Salsa20/20
state**. It does not search passwords or perform standard key expansion. Matching
requires a known keystream prefix: ciphertext XOR assumed plaintext.

## Build and tests

The GPU build requires an NVIDIA GPU, a compatible driver, the CUDA Toolkit with
`nvcc`, a C++17 compiler, and `make`. The supported GPU platform is Linux. Set
the target architecture explicitly; the Makefile defaults to `sm_80`:

```sh
make CUDA_ARCH=sm_89
```

For RTX Blackwell, use `make CUDA_ARCH=sm_120` and CUDA Toolkit 12.8 or later.
Pass compiler options through `CXX`, `CXXFLAGS`, `NVCC`, and `NVCCFLAGS`.

CPU tests do not require CUDA or a GPU:

```sh
make test
python3 -B -m unittest -v test_search_runner.py
make clean
```

C++ tests cover arguments, range boundaries, three Salsa20 reference blocks,
and all 64 byte positions. Python tests use a simulated worker to check search
resumption, shard boundaries, errors, and process termination.

Tests on an NVIDIA GeForce RTX 5090 showed 28–30 billion candidates/s for the
CUDA search tool. Throughput depends on search parameters and hardware.

## Commands

```text
./salsa_search search STATE_HEX OFFSETS_CSV TARGET_KEYSTREAM_HEX START COUNT [BATCH_COUNT] [MAX_SECONDS] [DEVICE] [THREADS]
./salsa_search blocks STATE_HEX OFFSETS_CSV START COUNT [DEVICE]
```

| Argument | Meaning |
|---|---|
| `STATE_HEX` | Exactly 128 hexadecimal characters, representing a 64-byte state |
| `OFFSETS_CSV` | One to five unique byte offsets in 0..63, such as `59,60,61,62,63`; this lists unknown positions, not a bitmask |
| `TARGET_KEYSTREAM_HEX` | One to 64 initial bytes of the expected keystream in hexadecimal |
| `START`, `COUNT` | Decimal integers; the half-open range `[START, START+COUNT)` must lie within `0..2^(8*N)`, where `N` is the number of unknown bytes |
| `BATCH_COUNT` | Batch size from 1 to 4294967295; default 16777216 |
| `MAX_SECONDS` | Nonnegative decimal value; 0 disables the limit and is the default |
| `DEVICE` | CUDA GPU index; default 0 |
| `THREADS` | Threads per block: a multiple of 32 from 32 to 1024; default 256; checked against the GPU hardware limit |

Candidate byte 0 replaces `state[offsets[0]]`, byte 1 replaces
`state[offsets[1]]`, and so on in little-endian order. Other state bytes remain
unchanged. The CUDA worker itself searches **at most 5 bytes (40 bits)**; it
does not distribute work across GPUs or resume automatically. Use the Python
module below for resumption.

Synthetic example with an all-zero state:

```sh
state_hex=$(printf '%0128d' 0)
./salsa_search blocks "$state_hex" 63 0 1
./salsa_search search "$state_hex" 63 00000000 0 256 256 1 0 256
```

`blocks` mode prints the complete 64-byte result for each candidate and limits
`COUNT` to 256. It uses the same Salsa20 primitive as search mode and can be
compared with an independent implementation.

## Results and limits

Output is JSONL: `device`, completed `batch` records with `hits` arrays, then
`summary`. In `blocks` mode, only `block` records with `candidate` and `hex` are
printed. Search continues after matches. **A matching prefix requires an
independent check of the complete file content.**

The time limit is checked between batches, so a running batch finishes. To
resume, use `summary.next_candidate` and reduce the remaining `COUNT`.
`batch.elapsed_seconds` measures GPU work; total time and throughput include
batch handling and output. Throughput depends on the GPU and should be measured
on the target system.

Exit codes: 2 for invalid arguments, 3 for CUDA or output errors, and 4 when
the 4096-match buffer overflows. On overflow, `type=error` is emitted; the
failed batch and final summary are not published. Reduce `BATCH_COUNT` or use a
longer target prefix. After a failure, do not treat the entire requested range
as tested: previously published batches describe only completed work.

## Python API and search resumption

`search_runner.run_search(worker, state_base, unknown_offsets, target, checkpoint_path, *, batch_count=2**28, threads=256, segment_seconds=30, status_callback=None)`
returns a candidate generator. It requires Python 3.10+ on a POSIX platform;
the GPU worker runs as a child process and uses CUDA device 0.

The module accepts 0 to **6 unknown bytes**. For 6 bytes, it fixes the sixth
byte in turn and runs 256 ranges of 40 bits. Support for 48 bits does not
guarantee practical search time; that depends on the GPU, target prefix, and
subsequent validation of matches.

This synthetic example checks all 256 values of the last byte in an all-zero state:

```python
from contextlib import closing
from pathlib import Path
from search_runner import run_search

with closing(run_search(
    Path("./salsa_search").resolve(),
    bytes(64),
    (63,),
    bytes(64),
    Path("private-checkpoints/demo.json"),
    batch_count=256,
    segment_seconds=1,
)) as candidates:
    for candidate in candidates:
        print("Candidate:", candidate)
```

Running again with the same checkpoint resumes the search; a different state,
set of offsets, or prefix causes an error. The checkpoint is written atomically
with `fsync` after all matches from a batch have been consumed. A `break` inside
`with closing(...)` stops the child process, and the unfinished batch is checked
again on resumption. `segment_seconds` limits one worker run, not the entire
search. The optional `status_callback` receives progress dictionaries.

**Keep checkpoints private:** they contain the state and target prefix. Store
them separately from published code. The generator yields keystream matches
only; for real files, the caller must independently verify content before
accepting a candidate.
