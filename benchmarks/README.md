# Benchmark

After installation, run these commands from the project root:

```sh
python -m pip install .
python benchmarks/benchmark.py
python benchmarks/benchmark.py --size-bytes 1048576 --json
```

The script uses reproducible synthetic data and an arbitrary 64-byte Salsa20
state. The default buffer size is 256 KiB. Before timing and after every sample,
it compares the output byte-for-byte with `salsa_crypt_python`. Timing includes
result allocation and the public function call; it excludes data preparation,
comparison, and SHA-256 calculation.

The Python implementation runs three samples. For the C implementation, the
number of calls doubles until a calibration sample takes at least 0.2 seconds;
then five samples run with that call count. The reported throughput uses the
median. The JSON report also includes minimum and maximum durations, platform,
Python version, repeat count, MiB/s, and speedup. Use `--python-samples` and
`--native-samples` to change the sample counts.

If the optional C extension is unavailable, the script reports this and
measures only Python. To test an in-place `build_ext --inplace` build without
installation, run `python -m benchmarks.benchmark --json` from the project root.

This benchmark measures in-memory Salsa20 computation. File recovery speed also
depends on disk performance, the fraction of encrypted data, and file size.
Compare builds using the same parameters and little background load.

## Example result

On macOS arm64 with CPython 3.14.6, on September 25, 2026, with a 256 KiB buffer:

| Implementation | Throughput |
| --- | ---: |
| Python | 1.282 MiB/s |
| C | 965.269 MiB/s |

The computation was about 753 times faster, and the results matched byte-for-byte.
This is one local measurement, not a guarantee of speed on another computer.
