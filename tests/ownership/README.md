# 4D ownership regressions

A synthetic-boundary ASan/UBSan harness that links the real `4DPlugin-cURL.cpp`,
`support/4DPlugin-JSON.cpp`, `include/ftpparse.c` and the unchanged bundled
4D Plugin API (`4DPluginAPI.c`, `C_TEXT`, `C_BLOB`, `C_LONGINT`) against:

- `main.mm`: a fake 4D engine behind `Call4D`. It tracks every engine string,
  object/collection, picture and handle, dies on double or foreign disposal and
  on clearing a poisoned variable, and fails a test when values are left alive.
- `curl_stubs.cpp`: deny-by-default libcurl, libproxy and libiconv fakes.
  No network, no TLS, no proxy lookup and no iconv conversion takes place.

```
python3 tests/ownership/run.py --tree . --out /tmp/own-fixed --expect-none
git archive cb612de632e5403f73fef23847b13549d3c68e1a | tar -x -C /tmp/own-base
python3 tests/ownership/run.py --tree /tmp/own-base --out /tmp/own-base-out \
    --expect tests/ownership/baseline-expected-failures.txt
```

`run.py` pins the git blob ids of every bundled SDK file, refuses to link
libcurl/OpenSSL/libproxy/libiconv, runs every `control_*` test (which must pass
on both trees) and the probes that prove the fake detects double disposal,
shallow aliasing, poisoned clears and denied boundaries.

`baseline-expected-failures.txt` names the tests that fail on the unfixed
source. See `.github/tests/ownership-audit.md` for the defects and evidence.
