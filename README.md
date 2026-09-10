# minimp3 Heap‑based Buffer Overflow Vulnerability

## Overview
- Library: minimp3, lightweight single‑header MP3 decoder
- CWE: CWE‑122 Heap‑based Buffer Overflow
- Vulnerable location: function `mp3d_synth_pair`, inside `minimp3.h`
- Attack vector: Remote, malicious MP3 file

A specially crafted malformed MP3 file can trigger an out‑of‑bounds 2‑byte heap write. When parsed by the decoder built with AddressSanitizer, it reports `heap‑buffer‑overflow`. This vulnerability may lead to application crash (denial of service) and potential arbitrary code execution.

## PoC artifact
PoC filename: `crash‑4e5d953857bf8d8ee81b4678da65e5cff741e350`
MD5 checksum: `5017a2ed28096d1be8b7926a4d406db5`

## Reproduction
1. Create libFuzzer fuzz harness including `minimp3.h`.
2. Compile using clang with AddressSanitizer and libFuzzer:
```bash
clang -fsanitize=address,fuzzer -g fuzz_harness.c -o fuzz_minimp3 -lm
3.Run compiled binary against the PoC file:
./fuzz_minimp3 crash‑4e5d953857bf8d8ee81b4678da65e5cff741e350
4.AddressSanitizer will trigger heap‑buffer‑overflow inside mp3d_synth_pair.
Files in this repository
crash-4e5d953857bf8d8ee81b4678da65e5cff741e350 — malformed MP3 PoC binary
minimp3_final_asan_log.txt — full raw AddressSanitizer crash log
asan_crash_screenshot.png — screenshot of ASan crash summary


md5sum of crash-4e5d953857bf8d8ee81b4678da65e5cff741e350 is
5017a2ed28096d1be8b7926a4d406db5 
