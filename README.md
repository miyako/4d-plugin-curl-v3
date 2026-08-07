![version](https://img.shields.io/badge/version-19%2B-5682DF)
![platform](https://img.shields.io/static/v1?label=platform&message=mac-intel%20|%20mac-arm%20|%20win-64&color=blue)
[![license](https://img.shields.io/github/license/miyako/4d-plugin-curl-v3)](LICENSE)
![downloads](https://img.shields.io/github/downloads/miyako/4d-plugin-curl-v3/total)

# 4d-plugin-curl-v3

The cURL plugin wraps [libcurl](https://curl.se/) to give 4D methods direct access to HTTP(S), FTP(S), and SFTP transfers, without shelling out or building your own socket code. It exposes two families of commands: a low-level, protocol-agnostic `cURL` command that maps a 4D object almost directly onto libcurl's own option set (`CURLOPT_*`), and a set of higher-level `cURL_FTP_*` commands for common FTP/SFTP operations (list, send, receive, rename, delete, make/remove directory, run a raw `SYST`/quote-style command). Results come back as 4D objects; transferred bytes come back as `Blob`s (or written straight to a file on disk, your choice).

## Summary

| Command | Returns | Purpose |
|---|---|---|
| [`cURL_VersionInfo`](#curl_versioninfo) | Object | Report the linked libcurl version, features, and supported protocols |
| [`cURL_Escape`](#curl_escape) | Text | URL-encode a string |
| [`cURL_Unescape`](#curl_unescape) | Text | URL-decode a string |
| [`cURL_GetDate`](#curl_getdate) | Longint | Parse an HTTP-style date string into a Unix timestamp |
| [`cURL`](#curl) | Object | Run any HTTP/HTTPS/FTP/SFTP/etc. transfer using libcurl's own option set |
| [`cURL_FTP_Delete`](#curl_ftp_delete) | Object | Delete a remote file |
| [`cURL_FTP_GetDirList`](#curl_ftp_getdirlist) | Object | List a remote directory, parsed into an object per entry |
| [`cURL_FTP_GetFileInfo`](#curl_ftp_getfileinfo) | Object | Get a remote file's size and modification date |
| [`cURL_FTP_MakeDir`](#curl_ftp_makedir) | Object | Create a remote directory |
| [`cURL_FTP_PrintDir`](#curl_ftp_printdir) | Object | List a remote directory as raw text (names only) |
| [`cURL_FTP_Receive`](#curl_ftp_receive) | Object | Download a remote file |
| [`cURL_FTP_RemoveDir`](#curl_ftp_removedir) | Object | Remove a remote (empty) directory |
| [`cURL_FTP_Rename`](#curl_ftp_rename) | Object | Rename/move a remote file |
| [`cURL_FTP_Send`](#curl_ftp_send) | Object | Upload a file |
| [`cURL_FTP_System`](#curl_ftp_system) | Object | Run the FTP `SYST` command (server system identification) |

**Platforms:** macOS and Windows.

---

## Requirements & platform notes

- **The `options` object is the plugin's real interface.** `cURL` and every `cURL_FTP_*` command take the same kind of `options` object as their first parameter, built almost entirely from libcurl's own `CURLOPT_*` constants (with the `CURLOPT_` prefix dropped — e.g. `CURLOPT_SSL_VERIFYPEER` becomes `$options.SSL_VERIFYPEER`). See [The options object](#the-options-object) below for the full key reference. Keys you don't set are simply left at libcurl's default.
- **TLS certificate verification needs a CA bundle.** Without one, HTTPS/FTPS requests to servers 4D doesn't already trust will fail (libcurl error 60). Download `cacert.pem` from [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) and set `$options.CAINFO` to its path. From the plugin's own test method (`TEST_https.4dm`):
  ```4d
  $options:=New object:C1471
  $options.URL:="https://download.4d.com/Products/Archives/Line_v11/11_9/Mac/DMGs/4D_v11_SQL_Release_9_US.dmg"
  $options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert-2021-01-19.pem").platformPath
  ```
- **Paths are platform-native, not POSIX**, per the plugin's own sample comments. Pass `.platformPath` (not `.path`) for every path-type option (`READDATA`, `WRITEDATA`, `CAINFO`, `SSLCERT`, `SSH_PRIVATE_KEYFILE`, `COOKIEFILE`, `DEBUG`, etc.). On macOS the plugin converts these internally before handing them to the OS file APIs.
- **`ATOMIC` only affects `cURL`, not any `cURL_FTP_*` command.** `cURL` has two internal execution modes:
  - **Default (`ATOMIC` unset or `false`):** the transfer runs in a polling loop that periodically yields to 4D, checks whether the calling process is being aborted (and cancels the transfer if so), and — if you passed a callback method name — invokes it roughly every 100ms with live progress plus once more when the transfer finishes.
  - **`ATOMIC:=true`:** the transfer runs as a single blocking `curl_easy_perform` call. It does **not** yield to 4D, is **not** cancellable by aborting the process, and **ignores the callback method entirely** even if you passed one. Only use this for requests you're confident will finish quickly.
  
  Every `cURL_FTP_*` command always uses the polling (non-atomic) mode — the plugin reads `ATOMIC` internally when building FTP options but never surfaces it, so setting it has no effect on `cURL_FTP_*` calls.
- **The progress callback has two different invocation styles depending on the name you pass**, and only one of them is the documented/intended usage:
  - **Pass the name of an existing 4D project method** (the common case — see [Callback method](#callback-method) below): the plugin calls it directly as `YourMethod($1:Object /* transferInfo */; $2:Text /* the PRIVATE option, if you set one */) -> Boolean` (return `True` to abort the transfer).
  - **Pass a name that does not resolve to an existing project method:** the plugin falls back to 4D's generic `EXECUTE METHOD` mechanism instead, which calls the target with a different parameter order (`$1:Boolean` abort flag in/out, `$2:Object` transferInfo, `$3:Text` userInfo). This path exists for dynamic/by-name dispatch and is not the common case — if your callback isn't firing as expected, double check the method name resolves to a real project method.
  - Passing an empty string (`""`) disables the callback entirely; the transfer still runs (and is still cancellable by aborting the process), it just never calls back.
- **`DEBUG` writes plaintext log files to disk** — full request/response headers, body data, and (if TLS is in use) the raw SSL record data, split into separate files per libcurl's own `CURLINFO_*` categories (`CURLINFO_TEXT.log`, `CURLINFO_HEADER_IN.log`, `CURLINFO_HEADER_OUT.log`, `CURLINFO_DATA_IN.log`, `CURLINFO_DATA_OUT.log`, `CURLINFO_SSL_DATA_IN.log`, `CURLINFO_SSL_DATA_OUT.log`). These can contain credentials, cookies, and auth headers in cleartext — treat the debug folder as sensitive and don't leave it turned on in production.
- **A 0-byte file passed via `READDATA`/`WRITEDATA` is indistinguishable from "no file"** in the current implementation — if the file that exists on disk happens to be genuinely empty, the plugin falls back to sending the in-memory `Blob` parameter instead of the (empty) file. This only matters if you're uploading/expecting a literal 0-byte file; anything with real content is unaffected.
- Every command in `manifest.json` is declared `threadSafe`, and each call gets its own libcurl "easy" handle (`curl_easy_init()` per call, not a shared one) — safe to call concurrently from multiple processes.

---

## cURL_VersionInfo

### Syntax
```
cURL_VersionInfo -> Object
```

No parameters.

| Parameter | Type | Description |
|---|---|---|
| `Result` | Object | libcurl version and capability info |

### Description
Returns a snapshot of `curl_version_info()`: the libcurl version string and numeric version, the host triplet it was built for, its feature bitmask, the linked SSL/TLS and zlib versions, and the list of protocols it was built to support. Depending on the libcurl build's reported "age," it may also include `libidn`, `libssh_version`, `brotli_version`, `nghttp2_version`, and `zstd_version` — these keys are simply absent on older libcurl builds rather than present-but-empty.

| Property | Type | Description |
|---|---|---|
| `version` | Text | libcurl version string, e.g. `"7.79.1"` |
| `version_num` | Longint | Numeric encoding of the version |
| `host` | Text | Build host triplet |
| `features` | Longint | Bitmask of `CURL_VERSION_*` feature flags |
| `ssl_version` | Text | Linked SSL/TLS library and version |
| `libz_version` | Text | Linked zlib version |
| `protocols` | Collection | Text entries, one per supported protocol scheme (`"http"`, `"ftp"`, `"sftp"`, ...) |
| `libidn` | Text | Present if the libcurl build reports it |
| `libssh_version` | Text | Present if the libcurl build reports it |
| `brotli_version` | Text | Present if the libcurl build reports it |
| `nghttp2_version` | Text | Present if the libcurl build reports it |
| `zstd_version` | Text | Present if the libcurl build reports it |

### Example
From the plugin's own test method (`TEST_version_info.4dm`):
```4d
$version:=cURL_VersionInfo

SET TEXT TO PASTEBOARD:C523(JSON Stringify:C1217($version; *))
```

Check for SFTP support before relying on it:
```4d
$version:=cURL_VersionInfo
$hasSFTP:=False:C215
If (Value type:C1509($version.protocols)=Is collection:K8:32)
    $hasSFTP:=$version.protocols.includes("sftp")
End if 
```

---

## cURL_Escape

### Syntax
```
cURL_Escape ( text ) -> Text
```

| Parameter | Type | Description |
|---|---|---|
| `text` | Text | String to URL-encode |
| `Result` | Text | URL-encoded string |

### Description
Percent-encodes every character that isn't unreserved (letters, digits, `-`, `.`, `_`, `~`), using libcurl's own `curl_easy_escape`. If the input is empty or encoding fails for any reason, the result is an empty string — there's no separate error signal.

### Example
```4d
$encoded:=cURL_Escape("hello world & friends")
 // $encoded = "hello%20world%20%26%20friends"
```

---

## cURL_Unescape

### Syntax
```
cURL_Unescape ( text ) -> Text
```

| Parameter | Type | Description |
|---|---|---|
| `text` | Text | Percent-encoded string to decode |
| `Result` | Text | Decoded string |

### Description
The inverse of `cURL_Escape`, via `curl_easy_unescape`. As with `cURL_Escape`, failure or an empty input just yields an empty result.

### Example
```4d
$decoded:=cURL_Unescape("hello%20world%20%26%20friends")
 // $decoded = "hello world & friends"
```

---

## cURL_GetDate

### Syntax
```
cURL_GetDate ( dateString ; *timestampText ) -> Longint
```

| Parameter | Type | Description |
|---|---|---|
| `dateString` | Text | A date string in any format `curl_getdate` understands (RFC 2822, RFC 850, asctime, ISO 8601, and several others) |
| `timestampText` | Text | *(by reference, optional)* receives the parsed Unix timestamp as text |
| `Result` | Longint | Parsed Unix timestamp (seconds since epoch), or `-1` if the string couldn't be parsed |

### Description
A thin wrapper over libcurl's `curl_getdate`, useful for parsing values out of HTTP headers like `Last-Modified` or `Date` without writing your own date-format matcher. The Longint result and the `timestampText` output parameter carry the same value (as text) when parsing succeeds; on failure both are `-1` / left unset respectively (`timestampText` is only written back when parsing succeeds).

Note the `Longint` result truncates a 64-bit `time_t` to a 32-bit value — for any realistic calendar date this is not a concern, but be aware the truncation exists if you're ever feeding it a deliberately out-of-range value.

### Example
```4d
$ts:=cURL_GetDate("Wed, 21 Oct 2015 07:28:00 GMT"; $tsText)
 // $ts = 1445412480, $tsText = "1445412480"

If ($ts=-1)
     // unparseable date string
End if 
```

---

## cURL

### Syntax
```
cURL ( options ; *request ; *response ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | Request configuration — see [The options object](#the-options-object) |
| `request` | Blob | *(by reference)* data to send (used when no `READDATA` path option is set) |
| `response` | Blob | *(by reference)* receives the downloaded data (used when no `WRITEDATA` path option is set) |
| `callbackMethod` | Text | *(optional)* name of a progress-callback method — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` — see below |

### Description
The general-purpose command: set `URL` and whatever other keys you need in `options`, and this drives libcurl's normal easy-interface transfer for HTTP, HTTPS, FTP, FTPS, SFTP, or anything else libcurl was built to support. Upload/download data can come from/go to either the in-memory `request`/`response` Blobs, or a file on disk via the `READDATA`/`WRITEDATA` path options — set the corresponding path option to use a file, or leave it unset to use the Blob.

The returned object always has:

| Property | Type | Description |
|---|---|---|
| `status` | Longint | libcurl's `CURLcode` for the transfer (`0` = `CURLE_OK`/success; see [libcurl's error code list](https://curl.se/libcurl/c/libcurl-errors.html) for anything else) |
| `transferInfo` | Object | Timing, size, and connection metadata — see [transferInfo fields](#transferinfo-fields) |
| `headerInfo` | Text | The raw response headers, as received |

### Example
From the plugin's own test method (`TEST_http_apple.4dm`):
```4d
C_OBJECT:C1216($vObj_Options;$vObj_Result)
C_BLOB:C604($vx_Request;$vx_Response)
C_TEXT:C284($vT_callback)
$vObj_Options:=New object:C1471
$vObj_Options.URL:="https://www.apple.com/test"

$vObj_Options.DEBUG:=Get 4D folder:C485(Logs folder:K5:19)
If (Application type:C494#4D Server:K5:6)
    SHOW ON DISK:C922(Get 4D folder:C485(Logs folder:K5:19);*)
End if 

$vT_callback:=""
$vObj_Result:=cURL ($vObj_Options;$vx_Request;$vx_Response;$vT_callback)
```

Downloading straight to disk instead of into a Blob, with certificate-chain info (from `issue_12.4dm`):
```4d
var $options; $status : Object
var $request; $response : Blob

$options:=New object:C1471
$options.URL:="https://www.apple.com/"
$options.CERTINFO:=1
$options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert-2021-01-19.pem").platformPath

$status:=cURL($options; $request; $response)
 // $status.transferInfo.certInfo is a collection of certificate-chain text lines
```

Uploading over SFTP with a private key, tracking progress via a named callback method (from `TEST_ftp_14.4dm`, adapted):
```4d
$options:=New object:C1471
$options.URL:="sftp://localhost:2222/Test.pdf"
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0
$options.UPLOAD:=1
$options.USERNAME:="tester"
$options.PASSWORD:="password"

C_BLOB:C604($request; $response)

$status:=cURL($options; $request; $response; "TEST_PROGRESS")
```

---

## The options object

`cURL` and every `cURL_FTP_*` command share this same `options` object shape. Most keys map straight onto a same-named libcurl `CURLOPT_*` constant (drop the `CURLOPT_` prefix to get the 4D key) — for the exact semantics of any option below, libcurl's own [`curl_easy_setopt` documentation](https://curl.se/libcurl/c/curl_easy_setopt.html) is the authoritative reference (search for `CURLOPT_<KEY>`). The tables below exist to tell you the *type* 4D should send and flag anything with plugin-specific behavior beyond a plain passthrough.

### Behavior / plugin-specific options

| Key | Type | Description |
|---|---|---|
| `URL` | Text | The request URL. Required for any transfer to happen. |
| `ATOMIC` | Boolean | `cURL` only (ignored by `cURL_FTP_*`) — see [Requirements](#requirements--platform-notes) for the behavioral difference this makes. |
| `PRIVATE` | Text | Arbitrary text passed through to your callback method as its `userInfo`/`$2` parameter; not sent to the server. |
| `READDATA` | Text (path) | File to read the upload body from, instead of the `request` Blob parameter. |
| `WRITEDATA` | Text (path) | File to write the downloaded body to, instead of filling the `response` Blob parameter. Missing parent folders are created automatically. |
| `AUTOPROXY` | Text | Any value triggers automatic proxy detection for the given `URL` via the OS proxy configuration (`libproxy`); sets `PROXY`/`PROXYTYPE` for you. The value itself isn't used, only its presence. |
| `DEBUG` | Text (path, folder) | Enables verbose logging to the given folder — see [Requirements](#requirements--platform-notes). |
| `DEBUG_ID` | Text | Optional subfolder name under `DEBUG`, useful for separating logs from concurrent/repeated calls. |
| `CERTINFO` | Boolean/Longint | Also collect the TLS certificate chain into `transferInfo.certInfo` (see [transferInfo fields](#transferinfo-fields)). |

### String options (passed through as-is)

`PROXY`, `USERPWD`, `PROXYUSERPWD`, `RANGE`, `REFERER`, `FTPPORT`, `USERAGENT`, `COOKIE`, `KEYPASSWD`, `CUSTOMREQUEST`, `INTERFACE`, `KRBLEVEL`, `RANDOM_FILE`, `EGDSOCKET`, `SSL_CIPHER_LIST`, `SSLCERTTYPE`, `SSLKEYTYPE`, `ACCEPT_ENCODING`, `FTP_ACCOUNT`, `COOKIELIST`, `FTP_ALTERNATIVE_TO_USER`, `SSH_HOST_PUBLIC_KEY_MD5`, `USERNAME`, `PASSWORD`, `PROXYUSERNAME`, `PROXYPASSWORD`, `NOPROXY`, `SSH_KNOWNHOSTS`, `RTSP_SESSION_ID`, `RTSP_STREAM_URI`, `RTSP_TRANSPORT`, `TLSAUTH_USERNAME`, `TLSAUTH_PASSWORD`, `TLSAUTH_TYPE`, `DNS_SERVERS`, `MAIL_AUTH`, `XOAUTH2_BEARER`, `DNS_INTERFACE`, `DNS_LOCAL_IP4`, `DNS_LOCAL_IP6`, `LOGIN_OPTIONS`, `PROXY_SERVICE_NAME`, `SERVICE_NAME`, `DEFAULT_PROTOCOL`, `PROXY_TLSAUTH_USERNAME`, `PROXY_TLSAUTH_PASSWORD`, `PROXY_TLSAUTH_TYPE`, `PROXY_SSLCERTTYPE`, `PROXY_SSLKEYTYPE`, `PROXY_KEYPASSWD`, `PROXY_SSL_CIPHER_LIST`, `PRE_PROXY`, `REQUEST_TARGET`, `TLS13_CIPHERS`, `PROXY_TLS13_CIPHERS`, `DOH_URL`. Each is Text, mapped straight to the identically-named `CURLOPT_*`.

`PINNEDPUBLICKEY` / `PROXY_PINNEDPUBLICKEY` — Text. Either a `sha256//<base64-hash>` pin string (passed straight through) or a platform-native file path (converted internally on macOS).

### Path options (platform-native path, converted internally on macOS)

`SSLCERT`, `COOKIEFILE`, `CAINFO`, `COOKIEJAR`, `SSLKEY`, `CAPATH`, `NETRC_FILE`, `SSH_PUBLIC_KEYFILE`, `SSH_PRIVATE_KEYFILE`, `CRLFILE`, `ISSUERCERT`, `PROXY_CAINFO`, `PROXY_CAPATH`, `PROXY_SSLCERT`, `PROXY_SSLKEY`, `PROXY_CRLFILE`. All Text, holding a platform path (use `.platformPath`, not `.path`).

### Numeric options (passed through as-is)

Send these as Longint (or Real for the handful noted as "large" below, which libcurl treats as 64-bit):

`PORT`, `TIMEOUT`, `LOW_SPEED_LIMIT`, `LOW_SPEED_TIME`, `CRLF`, `HEADER`, `NOBODY`, `FAILONERROR`, `UPLOAD`, `POST`, `DIRLISTONLY`, `APPEND`, `NETRC`, `FOLLOWLOCATION`, `PUT`, `AUTOREFERER`, `PROXYPORT`, `HTTPPROXYTUNNEL`, `SSL_VERIFYPEER`, `MAXREDIRS`, `FILETIME`, `MAXCONNECTS`, `FRESH_CONNECT`, `FORBID_REUSE`, `CONNECTTIMEOUT`, `HTTPGET`, `SSL_VERIFYHOST`, `FTP_USE_EPSV`, `DNS_CACHE_TIMEOUT`, `COOKIESESSION`, `BUFFERSIZE`, `UNRESTRICTED_AUTH`, `FTP_USE_EPRT`, `HTTPAUTH`, `FTP_CREATE_MISSING_DIRS`, `PROXYAUTH`, `FTP_RESPONSE_TIMEOUT`, `IPRESOLVE`, `IGNORE_CONTENT_LENGTH`, `FTP_SKIP_PASV_IP`, `FTP_FILEMETHOD`, `LOCALPORT`, `LOCALPORTRANGE`, `CONNECT_ONLY`, `SSL_SESSIONID_CACHE`, `SSH_AUTH_TYPES`, `FTP_SSL_CCC`, `TIMEOUT_MS`, `CONNECTTIMEOUT_MS`, `HTTP_TRANSFER_DECODING`, `HTTP_CONTENT_DECODING`, `NEW_FILE_PERMS`, `NEW_DIRECTORY_PERMS`, `POSTREDIR`, `PROXY_TRANSFER_MODE`, `ADDRESS_SCOPE`, `TFTP_BLKSIZE`, `PROTOCOLS`, `REDIR_PROTOCOLS`, `FTP_USE_PRET`, `RTSP_REQUEST`, `RTSP_CLIENT_CSEQ`, `RTSP_SERVER_CSEQ`, `WILDCARDMATCH`, `TRANSFER_ENCODING`, `ACCEPTTIMEOUT_MS`, `TCP_KEEPALIVE`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `SASL_IR`, `SSL_ENABLE_NPN`, `SSL_ENABLE_ALPN`, `EXPECT_100_TIMEOUT_MS`, `SSL_VERIFYSTATUS`, `SSL_FALSESTART`, `PATH_AS_IS`, `PIPEWAIT`, `STREAM_WEIGHT`, `TFTP_NO_OPTIONS`, `TCP_FASTOPEN`, `KEEP_SENDING_ON_ERROR`, `PROXY_SSL_VERIFYPEER`, `PROXY_SSL_VERIFYHOST`, `PROXY_SSL_OPTIONS`, `SUPPRESS_CONNECT_HEADERS`, `SOCKS5_AUTH`, `SSH_COMPRESSION`, `HAPPY_EYEBALLS_TIMEOUT_MS`, `HAPROXYPROTOCOL`, `DNS_SHUFFLE_ADDRESSES`, `DISALLOW_USERNAME_IN_URL`, `UPLOAD_BUFFERSIZE`, `UPKEEP_INTERVAL_MS`.

`RESUME_FROM` / `RESUME_FROM_LARGE`, `TIMEVALUE` / `TIMEVALUE_LARGE`, `MAXFILESIZE` / `MAXFILESIZE_LARGE`, `MAX_SEND_SPEED` / `MAX_SEND_SPEED_LARGE`, `MAX_RECV_SPEED` / `MAX_RECV_SPEED_LARGE` — both spellings are accepted and behave identically (they map to the same `_LARGE`/64-bit `CURLOPT_*` either way).

### Enum options (Text name **or** raw numeric value)

These accept either the symbolic libcurl constant name as Text (recommended — check libcurl's docs for the valid names per option) or the raw numeric constant as Longint:

| Key | Example Text values |
|---|---|
| `USE_SSL` | `"USESSL_NONE"`, `"USESSL_TRY"`, `"USESSL_CONTROL"`, `"USESSL_ALL"` |
| `SSLVERSION` / `PROXY_SSLVERSION` | `"SSLVERSION_DEFAULT"`, `"SSLVERSION_TLSv1_2"`, `"SSLVERSION_TLSv1_3"`, `"SSLVERSION_MAX_TLSv1_3"`, ... |
| `HTTP_VERSION` | `"HTTP_VERSION_1_1"`, `"HTTP_VERSION_2"`, `"HTTP_VERSION_2TLS"`, `"HTTP_VERSION_2_PRIOR_KNOWLEDGE"`, ... |
| `TIMECONDITION` | `"TIMECOND_IFMODSINCE"`, `"TIMECOND_IFUNMODSINCE"`, `"TIMECOND_LASTMOD"` |
| `PROXYTYPE` | `"PROXY_HTTPS"`, `"PROXY_SOCKS4"`, `"PROXY_SOCKS4A"`, `"PROXY_SOCKS5"` |
| `FTPSSLAUTH` | `"FTPAUTH_SSL"`, `"FTPAUTH_TLS"` |
| `HEADEROPT` | `"HEADER_UNIFIED"`, `"HEADER_SEPARATE"` |

If you pass a Text value the plugin doesn't recognize, the option is silently left unset (no error) — double-check spelling against the table above.

### Array options (Collection of Text)

`CONNECT_TO`, `PROXYHEADER`, `HTTPHEADER`, `HTTP200ALIASES`, `RESOLVE`, `MAIL_RCPT`, `PREQUOTE`, `POSTQUOTE`, `QUOTE`, `TELNETOPTIONS` — each takes a Collection where every element is a Text line, mapped to libcurl's `curl_slist`-based options. Empty-string elements are skipped.

```4d
$options.HTTPHEADER:=New collection:C1472("Authorization: Bearer "+$token; "Accept: application/json")
```

> **`MAIL_FROM` is currently a no-op.** It's accepted by 4D's own JSON layer but never actually reaches libcurl in this build — if you need `CURLOPT_MAIL_FROM`, it isn't wired up yet.

### transferInfo fields

Every result from `cURL`/`cURL_FTP_*` includes a `transferInfo` object with this shape (fields simply absent if the underlying `curl_easy_getinfo` call fails for that field):

**Timing (microseconds converted from libcurl's `_T` timers):** `totalTime`, `nameLookupTime`, `connectTime`, `appConnectTime`, `preTransferTime`, `startTransferTime`, `redirectTime`.

**Size/speed:** `speedUpload`, `speedDownload`, `sizeUpload`, `sizeDownload`, `contentLengthUpload`, `contentLengthDownload` (normalized to `0` rather than libcurl's `-1` for a 0-byte SFTP file).

**Response/connection:** `responseCode`, `connectCode`, `httpVersion`, `redirectCount`, `headerSize`, `requestSize`, `sslVerifyResult`, `proxySslVerifyResult`, `localPort`, `primaryPort`, `numConnects`, `osErrNo`, `httpAuthAvail`, `proxyAuthAvail`, `protocol`, `proxyError`, `conditionUnmet`.

**File/socket:** `fileTime`, `lastSocket`, `retryAfter`.

**RTSP:** `rtspClientCseq`, `rtspServerCseq`, `rtspCseqRecv`.

**Strings:** `effectiveUrl`, `effectiveMethod`, `redirectUrl`, `contentType`, `ftpEntryPath`, `localIp`, `primaryIp`, `rtspSessionId`, `scheme`.

**Certificates:** `certInfo` — a Collection of Text lines (only present if you set `CERTINFO:=1`).

### Callback method

If you pass a non-empty `callbackMethod`/`callbackMethod` name that resolves to a real 4D project method, that method is called during the transfer (roughly every 100ms, plus once more at completion) with:

```4d
 // TEST_PROGRESS.4dm — the plugin's own test callback
C_OBJECT:C1216($1)   //transferInfo, same shape as above
C_TEXT:C284($2)      //the PRIVATE option you set, if any
C_BOOLEAN:C305($0)   //return True to abort the transfer
```

Returning `True` aborts the transfer (`status` comes back as libcurl's `CURLE_ABORTED_BY_CALLBACK`).

---

## cURL_FTP_Delete

### Syntax
```
cURL_FTP_Delete ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | Must include `URL` pointing at the file to delete; see [The options object](#the-options-object) |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` |

### Description
Deletes a single remote file. Internally this issues an FTP `DELE` (or, over SFTP, `rm`) as a quote command against the file's path — it does not require the server to support any special "delete" verb beyond standard FTP/SFTP.

### Example
From the plugin's own test method (`issue_5a.4dm`):
```4d
$options:=New object:C1471
$options.USERNAME:=""
$options.PASSWORD:=""
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0
$options.USE_SSL:="USESSL_ALL"
$options.URL:="ftps://.../test/upload.zip"

$status:=cURL_FTP_Delete ($options)
```

---

## cURL_FTP_GetDirList

### Syntax
```
cURL_FTP_GetDirList ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at a directory (trailing `/`); optionally set `FTP_USE_MLSD` — see below |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo ; dirList ; ftpparse }` |

### Description
Lists a remote directory and parses the listing for you. The raw listing text comes back in `dirList`; the parsed, per-entry breakdown comes back in `ftpparse`, a Collection whose shape depends on `FTP_USE_MLSD`:

- **`FTP_USE_MLSD` unset/`false` (default, uses `LIST`):** each collection element is an object parsed by the bundled `ftpparse` library, with fields `name`, `id`, `flagtrycwd`, `flagtryretr`, `size`, `sizetype`, `idtype`, and (when available) `mtimetype` and `mtime` (ISO 8601 text). A line the parser can't understand becomes a `Null` element in the collection rather than being dropped, so the collection length still matches the number of listing lines.

  > **Known quirk:** `sizetype` currently ends up holding the *raw numeric* `FTPPARSE_SIZE_*` code (`0`=unknown, `1`=binary, `2`=ASCII) rather than the string name (`"UNKNOWN"`/`"BINARY"`/`"ASCII"`) the plugin's own code computes just before it — a later line overwrites the string with the number under the same key. If you need the human-readable form, map the number yourself for now.
- **`FTP_USE_MLSD:=true` (uses `MLSD`; `ftpparse` doesn't understand MLSD, so a separate parser is used):** each collection element is an object with one Text property per semicolon-separated MLSD "fact" the server sent (e.g. `Type`, `Size`, `Modify` — exact keys are server-dependent, taken verbatim from the response), plus a `path` property with the entry's name. Lines with no discoverable path are skipped entirely (not represented in the collection at all — unlike the non-MLSD case, there's no `Null` placeholder here).

### Example
From the plugin's own test method (`TEST_ftp_dirlist.4dm`):
```4d
C_OBJECT:C1216($options; $status)

$options:=New object:C1471
$options.USERNAME:=""
$options.PASSWORD:=""
$options.URL:=""

$status:=cURL_FTP_GetDirList($options)  //folder must be empty
```

Using MLSD instead of LIST (from `issue_18.4dm`):
```4d
var $options; $status : Object
var $request; $response : Blob
var $callback : Text

$options:=New object:C1471
$options.URL:=""
$options.USERNAME:=""
$options.PASSWORD:=""
$options.FTP_USE_MLSD:=True:C214  //send MLSD instead of LIST

$status:=cURL_FTP_GetDirList($options)
```

Walking the parsed result:
```4d
For each ($entry; $status.ftpparse)
    If (Value type:C1509($entry)#Is null:K8:2)
        ALERT:C41($entry.name+" — "+String:C10($entry.size)+" bytes")
    End if 
End for each 
```

---

## cURL_FTP_GetFileInfo

### Syntax
```
cURL_FTP_GetFileInfo ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at the file to inspect |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo ; fileInfo }` |

### Description
A HEAD-style request (`NOBODY`) that retrieves a remote file's size and modification time without downloading it. `fileInfo.size` is normalized to `0` (rather than libcurl's `-1`) for a 0-byte file over SFTP specifically; `fileInfo.date`, when the server reports a file time, is an ISO 8601 UTC string (`"YYYY-MM-DDTHH:MM:SSZ"`).

| Property | Type | Description |
|---|---|---|
| `size` | Longint | File size in bytes |
| `date` | Text | Modification date/time, UTC, ISO 8601 — only present if the server returned one |

### Example
```4d
$options:=New object:C1471
$options.URL:="ftp://ftp.example.com/incoming/report.csv"
$options.USERNAME:="user"
$options.PASSWORD:="pass"

$status:=cURL_FTP_GetFileInfo($options)
If ($status.status=0)
    ALERT:C41("Size: "+String:C10($status.fileInfo.size))
End if 
```

---

## cURL_FTP_MakeDir

### Syntax
```
cURL_FTP_MakeDir ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at the directory to create |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` |

### Description
Creates the directory named by `URL` via an `MKD` (FTP) or `mkdir` (SFTP) quote command. The plugin automatically ensures the URL ends with a trailing `/` before sending it, so `.../new_folder` and `.../new_folder/` behave the same. Creating a directory that already exists returns a non-zero `status` (the server's own error), not a silent success.

### Example
```4d
$options:=New object:C1471
$options.URL:="ftp://ftp.example.com/incoming/2026-08-07"
$options.USERNAME:="user"
$options.PASSWORD:="pass"

$status:=cURL_FTP_MakeDir($options)
```

---

## cURL_FTP_PrintDir

### Syntax
```
cURL_FTP_PrintDir ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at a directory |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo ; dirList }` |

### Description
A lighter-weight alternative to `cURL_FTP_GetDirList`: sends `NLST` (via `DIRLISTONLY`) instead of `LIST`/`MLSD`, so the server returns only names, one per line, with no size/date/permission metadata. `dirList` is that raw text — there's no parsed `ftpparse`-style collection for this command.

### Example
```4d
$options:=New object:C1471
$options.URL:="ftp://ftp.example.com/incoming/"
$options.USERNAME:="user"
$options.PASSWORD:="pass"

$status:=cURL_FTP_PrintDir($options)
$names:=Split string:C1554($status.dirList; Char:C91(Carriage return:K15:38))
```

---

## cURL_FTP_Receive

### Syntax
```
cURL_FTP_Receive ( options ; *response ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at the file to download |
| `response` | Blob | *(by reference)* receives the downloaded bytes, unless `WRITEDATA` is set in `options` |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` |

### Description
Downloads a single file. As with `cURL`, you can either collect the bytes into the `response` Blob parameter (the default) or write them straight to disk by setting `WRITEDATA` in `options` — in that case `response` comes back empty (the plugin still needs the parameter, it just won't be used).

### Example
```4d
C_BLOB:C604($response)

$options:=New object:C1471
$options.URL:="sftp://server/Test.pdf"
$options.USERNAME:="tester"
$options.PASSWORD:="password"

$status:=cURL_FTP_Receive($options; $response)
```

Writing directly to disk instead:
```4d
$options:=New object:C1471
$options.URL:="sftp://server/Test.pdf"
$options.USERNAME:="tester"
$options.PASSWORD:="password"
$options.WRITEDATA:=Folder:C1567(fk desktop folder:K87:19).file("Test.pdf").platformPath

C_BLOB:C604($response)  //still required, comes back empty
$status:=cURL_FTP_Receive($options; $response)
```

---

## cURL_FTP_RemoveDir

### Syntax
```
cURL_FTP_RemoveDir ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at the (empty) directory to remove |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` |

### Description
Removes a remote directory via `RMD` (FTP) or `rmdir` (SFTP). Most servers require the directory to be empty first — a non-empty directory typically comes back as a non-zero `status` rather than a recursive delete.

### Example
From the plugin's own test method (`issue_5b.4dm`):
```4d
C_OBJECT:C1216($options;$status)

$options:=New object:C1471
$options.USERNAME:="miyako"
$options.FTP_CREATE_MISSING_DIRS:=1
$options.SSH_AUTH_TYPES:=1  //CURLSSH_AUTH_PUBLICKEY
$options.KEYPASSWD:="pass"
$options.SSH_PRIVATE_KEYFILE:=Folder:C1567(fk desktop folder:K87:19).file("id_rsa").platformPath
$options.URL:="sftp://100.64.1.57/Users/miyako/Desktop/test/"

$status:=cURL_FTP_RemoveDir ($options)  //folder must be empty
```

---

## cURL_FTP_Rename

### Syntax
```
cURL_FTP_Rename ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` = the file's current path; `RENAME_TO` = the new name/path |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` |

### Description
Renames or moves a remote file. Over plain FTP this is two quote commands (`RNFR`/`RNTO`); over SFTP it's a single `rename` quote command. Set `RENAME_TO` to either just a new filename (rename in place) or a full new path (move), matching whatever the target server accepts for its rename command.

### Example
```4d
$options:=New object:C1471
$options.URL:="ftp://ftp.example.com/incoming/report.csv"
$options.USERNAME:="user"
$options.PASSWORD:="pass"
$options.RENAME_TO:="report-2026-08-07.csv"

$status:=cURL_FTP_Rename($options)
```

---

## cURL_FTP_Send

### Syntax
```
cURL_FTP_Send ( options ; *request ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at the destination file; set `UPLOAD` is implied automatically, no need to set it yourself |
| `request` | Blob | *(by reference)* data to upload, unless `READDATA` is set in `options` |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo }` |

### Description
Uploads a single file. As with `cURL_FTP_Receive`, either supply the bytes in the `request` Blob (the default) or point `READDATA` at a file on disk to stream it straight from there — most efficient for large files, since it avoids holding the whole thing in memory.

### Example
From the plugin's own test method (`TEST_ftp_upload.4dm`):
```4d
$file:=Folder:C1567(fk desktop folder:K87:19).file("vcpkg-master.zip")

$options:=New object:C1471
$options.URL:="sftp://.../"+$file.name+$file.extension
$options.UPLOAD:=1
$options.USERNAME:=""
$options.PASSWORD:=""
$options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert-2021-01-19.pem").platformPath
$options.BUFFERSIZE:=2000000
$options.READDATA:=$file.platformPath

C_BLOB:C604($request;$response)

$vt_callback:=""
$ob_status:=cURL_FTP_Send ($options;$request;$vt_callback)
```

---

## cURL_FTP_System

### Syntax
```
cURL_FTP_System ( options ; *callbackMethod ) -> Object
```

| Parameter | Type | Description |
|---|---|---|
| `options` | Object | `URL` should point at the server (path portion is ignored for this command) |
| `callbackMethod` | Text | *(optional)* — see [Callback method](#callback-method) |
| `Result` | Object | `{ status ; transferInfo ; headerInfo ; system }` |

### Description
Sends the FTP `SYST` command and returns the server's raw system-identification response in `system` (e.g. `"215 UNIX Type: L8"`). Mainly useful for diagnostics — most servers respond to this even when locked down for everything else.

### Example
```4d
$options:=New object:C1471
$options.URL:="ftp://ftp.example.com/"
$options.USERNAME:="user"
$options.PASSWORD:="pass"

$status:=cURL_FTP_System($options)
ALERT:C41($status.system)
```

---

## Error handling & troubleshooting

- **`status` of `0` means success; anything else is a libcurl `CURLcode`.** Check `status.transferInfo.responseCode` for the HTTP status code (200, 404, etc.) separately — a `status` of `0` only means the *transfer mechanics* succeeded, not that the server returned a 2xx response. Set `FAILONERROR:=1` if you want libcurl itself to treat a 4xx/5xx HTTP response as a transfer failure.
- **SSL error 60 ("certificate problem")** almost always means `CAINFO` isn't set, or points at a bundle 4D can't reach at that path — see [Requirements](#requirements--platform-notes).
- **A callback that never fires** usually means either the name doesn't resolve to a real project method (check spelling/scope) or `ATOMIC:=true` is set (which silently disables the callback for `cURL`, and has no effect at all — silently — on `cURL_FTP_*`).
- **`cURL_FTP_MakeDir`/`RemoveDir`/`Rename`/`Delete` "succeed" with the wrong `status`**: these all report the server's actual quote-command response code, so check `status` (and `headerInfo`) rather than assuming a call that returned always means the operation actually happened as expected — e.g. removing a non-empty directory typically comes back as a real error from the server, not from the plugin.
- **Paths silently do nothing**: if a path-type option (`READDATA`, `CAINFO`, `SSH_PRIVATE_KEYFILE`, etc.) is a POSIX path on macOS instead of `.platformPath`, expect an obscure open/read failure rather than a clear error — always use `.platformPath`.
- **A 0-byte upload file behaves like no file was given** — see [Requirements](#requirements--platform-notes).
- **`ftpparse`'s `sizetype` is numeric, not the string name** — see the callout under [cURL_FTP_GetDirList](#curl_ftp_getdirlist).
- **Debug logs accumulate on disk** — each `DEBUG`-enabled call appends to the same log files rather than overwriting them (unless the specific log file couldn't be opened, in which case that one entry is simply lost); use `DEBUG_ID` to separate runs, and clean the folder out periodically.

---

## Quick reference

```4d
 // Simple GET into a Blob
C_BLOB:C604($request;$response)
$options:=New object:C1471
$options.URL:="https://example.com/data.json"
$options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert.pem").platformPath
$status:=cURL($options;$request;$response)

 // FTP upload from disk
$options:=New object:C1471
$options.URL:="sftp://host/path/file.zip"
$options.USERNAME:="user"
$options.PASSWORD:="pass"
$options.READDATA:=$file.platformPath
C_BLOB:C604($request)
$status:=cURL_FTP_Send($options;$request;"")

 // FTP directory listing
$options:=New object:C1471
$options.URL:="ftp://host/incoming/"
$options.USERNAME:="user"
$options.PASSWORD:="pass"
$status:=cURL_FTP_GetDirList($options)
For each ($entry;$status.ftpparse)
     // ...
End for each 
```
