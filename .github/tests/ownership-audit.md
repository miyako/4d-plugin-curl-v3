# 4D ownership audit (strings, variables, pictures)

Audited against the bundled, unchanged 4D Plugin API (`4D Plugin API/`) at base
`cb612de632e5403f73fef23847b13549d3c68e1a`. Scope: every manifest command, all
native helpers in `4DPlugin-cURL.cpp` and `support/4DPlugin-JSON.cpp`, every
member of `cURL.xcodeproj` and `cURL.vcxproj`, and dormant code.

## Contracts

1. A successful `PA_SetStringInArray` / `PA_SetPictureInArray` takes ownership.
2. Array and parameter getters return borrowed values.
3. `PA_CreateVariable(eVK_Unistring | eVK_Picture)` allocates an empty owner;
   a shallow `PA_SetStringVariable` / `PA_SetPictureVariable` overwrites it
   without disposal. Create with `eVK_Undefined` and set once.
4. `PA_ExecuteMethodByID` results, `PA_GetObjectProperty` and
   `PA_GetCollectionElement` results are owned copies (`PA_SetCollectionElement`
   deep-copies). Check `PA_GetLastError()` first; clear only on `eER_NoErr`.

## Confirmed defects (fixed)

| Id | Site | Defect |
|----|------|--------|
| A | `curl_get_info` certInfo | `eVK_Unistring` + shallow set leaks one empty string per certificate line |
| B | `VersionInfo` protocols | same pattern, one string per protocol |
| C | `curl_perform_non_atomic` | `method` unistring created on every path (leaked without the EXECUTE METHOD path); `cbparams[0]` created as `eVK_Unistring` then overwritten |
| D | `curl_perform_non_atomic` | each tick and the final callback overwrite the `transferInfo` object variable without clearing the previous object |
| E | `curl_perform_non_atomic` | `PA_ExecuteMethodByID` results (tick and final) never cleared; text/object results leak |
| F | `curl_easy_setopt_array` + 10 callers | element copies from `PA_GetCollectionElement` never cleared; the collection returned by `ob_get_c` never disposed |
| G | `support/4DPlugin-JSON.cpp` | `ob_set_s` (×2), `ob_set_a` (×2), `ob_set_p` empty owners; `ob_get_a` never clears its copy; `ob_get_b`, `ob_get_n`, `ob_get_c` leak the owned copy on a type mismatch |

`ob_get_c` now transfers ownership of the returned collection to the caller;
its only callers are the `curl_easy_setopt_array` sites, which dispose it.

## Evidence

The same harness (`tests/ownership/`) runs on the immutable baseline
(`git archive` of the base SHA) and on the fixed tree:

- baseline: 16 passed, 43 failed, exactly the names in
  `tests/ownership/baseline-expected-failures.txt`, all failing on leaked
  engine values (e.g. `command_version_info` 16 strings,
  `curl_callback_method_result_object` 56 strings + 7 objects).
- fixed: 59/59 passed; all probes behave.
- hybrid (baseline plugin + fixed JSON helpers): 15 plugin tests still fail
  (e.g. `command_version_info` 7 strings = 7 protocols; `curl_atomic_headers_certinfo`
  8 strings + 2 objects = 4 cert lines + 4 header copies + 1 object element + the
  collection; `curl_callback_method_result_text` +3 result texts), showing A–F are
  independent of G.

Controls (escape/unescape/getDate, scalar and object setters, matching getters,
failed getters with poisoned results, `PA_ExecuteMethodByID` failure with a
poisoned result) pass on both trees, so the fixes never clear what they do not own.

## Not defects

- `ob_set_o/c/n/i/b/0`, `ob_is_defined`, `ob_stringify` (correct; no caller, dormant).
- FTP `GetDirList` list and MLSD parsing, `GetFileInfo`; the `eVK_Null` element.
- `PA_SetUnistring` into `cbparams` userInfo (replaces in place).
- `PA_ExecuteCommandByID` 323 (DELAY PROCESS), 672 (Boolean), 1007 (no owned result).
- libcurl write/read/header/debug callbacks make no 4D calls; progress is off (`NOPROGRESS`).
- `C_TEXT`, `C_BLOB`, `C_LONGINT` usage.
- `4D Plugin API/Classes/ARRAY_TEXT.cpp`: correct and in neither build (dormant).

## Reachability and gaps

- `ob_set_p` has no caller (dormant); fixed for consistency with contract 3.
- Not validated: Windows (the `_WIN32` branches compile only on Windows), a real
  4D engine, real libcurl/OpenSSL transfers, or LeakSanitizer (the fake engine's
  live-value accounting is the leak oracle). Bundled libcurl/OpenSSL sources and
  binaries are out of scope.
