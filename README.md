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

## Files in this repository
1. [crash-4e5d953857bf8d8ee81b4678da65e5cff741e350](./crash-4e5d953857bf8d8ee81b4678da65e5cff741e350) — malformed MP3 PoC binary
2. [linenumberminimp3.txt.txt](./linenumberminimp3.txt.txt) — full raw AddressSanitizer crash log
3. [minimp3heap1.png](./minimp3heap1.png) — ASan crash screenshot 1
4. [minimp3heap2.png](./minimp3heap2.png) — ASan crash screenshot 2
5. [minimp3heap3.png](./minimp3heap3.png) — ASan crash screenshot 3
6. [minimp3heap4.png](./minimp3heap4.png) — ASan crash screenshot 4

Asan crash log is as follows: (also in attached files)
ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer) ./fuzz_iterate ./crash-4e5d953857bf8d8ee81b4678da65e5cff741e350 2>&1 > minimp3_cve_symbolized.txt
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3597874590
INFO: Loaded 1 modules   (1002 inline 8-bit counters): 1002 [0x5cd7756d7890, 0x5cd7756d7c7a),
INFO: Loaded 1 PC tables (1002 PCs): 1002 [0x5cd7756d7c80,0x5cd7756dbb20),
./fuzz_iterate: Running 1 inputs 1 time(s) each.
Running: ./crash-4e5d953857bf8d8ee81b4678da65e5cff741e350
=================================================================
==5063==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x619000000a02 at pc 0x5cd77569176a bp 0x7fff4eb1f540 sp 0x7fff4eb1f538
WRITE of size 2 at 0x619000000a02 thread T0
    #0 0x5cd775691769 in mp3d_synth_pair /home/lloyd/Documents/minimp3-master/./minimp3.h:1462:12
    #1 0x5cd7756819a7 in mp3d_synth /home/lloyd/Documents/minimp3-master/./minimp3.h:1513:5
    #2 0x5cd7756819a7 in mp3d_synth_granule /home/lloyd/Documents/minimp3-master/./minimp3.h:1641:9
    #3 0x5cd7756796c7 in mp3dec_decode_frame /home/lloyd/Documents/minimp3-master/./minimp3.h:1774:17
    #4 0x5cd77568ef75 in frames_iterate_cb /home/lloyd/Documents/minimp3-master/fuzz_iterate.c:41:11
    #5 0x5cd775687d14 in mp3dec_iterate_buf /home/lloyd/Documents/minimp3-master/./minimp3_ex.h:557:24
    #6 0x5cd77568ec42 in LLVMFuzzerTestOneInput /home/lloyd/Documents/minimp3-master/fuzz_iterate.c:65:11
    #7 0x5cd77559d3a3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x453a3) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #8 0x5cd77558711f in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x2f11f) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #9 0x5cd77558ce76 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x34e76) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #10 0x5cd7755b6c92 in main (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x5ec92) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #11 0x7efac8a29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #12 0x7efac8a29e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #13 0x5cd7755819e4 in _start (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x299e4) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)

0x619000000a02 is located 2 bytes to the right of 1152-byte region [0x619000000580,0x619000000a00)
allocated by thread T0 here:
    #0 0x5cd775639a1e in malloc (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0xe1a1e) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #1 0x5cd77568eeef in frames_iterate_cb /home/lloyd/Documents/minimp3-master/fuzz_iterate.c:37:27
    #2 0x5cd775687d14 in mp3dec_iterate_buf /home/lloyd/Documents/minimp3-master/./minimp3_ex.h:557:24
    #3 0x5cd77568ec42 in LLVMFuzzerTestOneInput /home/lloyd/Documents/minimp3-master/fuzz_iterate.c:65:11
    #4 0x5cd77559d3a3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x453a3) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #5 0x5cd77558711f in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x2f11f) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #6 0x5cd77558ce76 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x34e76) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #7 0x5cd7755b6c92 in main (/home/lloyd/Documents/minimp3-master/fuzz_iterate+0x5ec92) (BuildId: 7a0d97adf3f176bb201e3da79f7b92559764dff2)
    #8 0x7efac8a29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/lloyd/Documents/minimp3-master/./minimp3.h:1462:12 in mp3d_synth_pair
Shadow bytes around the buggy address:
  0x0c327fff80f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff8130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c327fff8140:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8150: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8160: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8170: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8190: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==5063==ABORTING

