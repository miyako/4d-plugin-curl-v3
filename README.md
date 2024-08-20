![version](https://img.shields.io/badge/version-19%2B-5682DF)
![platform](https://img.shields.io/static/v1?label=platform&message=mac-intel%20|%20mac-arm%20|%20win-64&color=blue)
[![license](https://img.shields.io/github/license/miyako/4d-plugin-curl-v3)](LICENSE)
![downloads](https://img.shields.io/github/downloads/miyako/4d-plugin-curl-v3/total)

# 4d-plugin-curl-v3
Generic network client based on libcurl.

* macOS library version:
  * `libcurl-8.9.1`
  * `openssl-3.3.1` 
  * `libz-1.2.11`
  * `libssh2-1.11.0`
  * `brotli-1.0.9`
  * `nghttp2-1.61.0`
  * `zstd-1.5.6`

* Windows library version:
  * `libcurl-8.9.1`
  * `openssl-3.3.1 (Schannel)`
  * `libz-1.3.1`
  * `libssh2-1.11.0`
  * `brotli-1.1.0`
  * `nghttp2-1.62.1`
  * `zstd-1.5.5`

vcpkg configuration: `[brotli,c-ares,core,http2,idn2,non-http,openssl,schannel,ssh,ssl,sspi,winldap,zstd] --triplet x64-windows-static`

* missing protocol on Windows: rtmp, rtmpe, rtmps, rtmpt, rtmpte, rtmpts

* callback frequency increased: from every `1` second to every `100` milliseconds max

* removed Windows 32-bit support

* JSON parameters are now native objects:

```4d
Text:=cURL_VersionInfo()
Object:=cURL_VersionInfo()
 
Long:=cURL(Text;Blob;Blob;Text;Text;Text)
Object:=cURL(Object;Blob;Blob;Text)

curl_callback_method(Text;Text) => Bool
curl_callback_method(Object;Text) => Bool
```

* integrated high-level FTP commands in `4.0.0`

#### FTP high-level commands

new syntax for `cURL_FTP_Receive` and `cURL_FTP_Send`

Parameter|Type|Description
------------|------------|----
options|OBJECT|
data|BLOB|
callbackMethod|TEXT|optional
status|OBJECT|

use `CURLOPT_READDATA` `CURLOPT_WRITEDATA` to specify a path in/out (same as cURL)

otherwise pass a BLOB in `$2`

new syntax for all other commands

Parameter|Type|Description
------------|------------|----
options|OBJECT|
callbackMethod|TEXT|optional
status|OBJECT|

use `FTP_CREATE_MISSING_DIRS` option with `cURL_FTP_Send` and `cURL_FTP_MakeDir`

use `WILDCARDMATCH` option with `cURL_FTP_Receive` 

---

Properties of ``curlInfo``

```
conditionUnmet
contentLengthUpload
rtspClientCseq
rtspServerCseq
rtspCseqRecv
lastSocket
primaryPort
localPort
contentLengthDownload
connectCode
fileTime
totalTime
requestSize
headerSize
speedUpload
speedDownload
sizeDownload
sizeUpload
httpAuthAvail
proxyAuthAvail
osErrNo
numConnects
responseCode
nameLookupTime
connectTime
appConnectTime
preTransferTime
startTransferTime
redirectTime
sslVerifyResult
redirectCount
effectiveUrl
localIp
contentType
primaryIp
redirectUrl
ftpEntryPath
rtspSessionId
```

---

Special ``options``

Value|Type|Description
------------|------------|----
[PRIVATE](https://curl.haxx.se/libcurl/c/CURLOPT_PRIVATE.html) |TEXT|context info passed to ``callbackMethod``
[READDATA](https://curl.haxx.se/libcurl/c/CURLOPT_READDATA.html) |TEXT|use file path instead of ``request``
[WRITEDATA](https://curl.haxx.se/libcurl/c/CURLOPT_WRITEDATA.html) |TEXT|use file path instead of ``response``
AUTOPROXY |LONGINT|``1`` to use ``libproxy``
ATOMIC |BOOLEAN|``True`` to use simple (as opposed to multiple) API
[DEBUG](https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html) |TEXT|folder path to create log files
FTP_USE_MLSD|BOOLEAN|``True`` to use `MLSD` instead of `LIST`

---

Standard  ``options``

Value|Type|Description
------------|------------|----
[URL](https://curl.haxx.se/libcurl/c/CURLOPT_URL.html) |TEXT|
[PORT](https://curl.haxx.se/libcurl/c/CURLOPT_PORT.html) |LONGINT|
[PROXY](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html) |TEXT|
[USERPWD](https://curl.haxx.se/libcurl/c/CURLOPT_USERPWD.html) |TEXT|
[PROXYUSERPWD](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYUSERPWD.html) |TEXT|
[RANGE](https://curl.haxx.se/libcurl/c/CURLOPT_RANGE.html) |TEXT|
[TIMEOUT](https://curl.haxx.se/libcurl/c/CURLOPT_TIMEOUT.html) |LONGINT|
[REFERER](https://curl.haxx.se/libcurl/c/CURLOPT_REFERER.html) |TEXT|
[FTPPORT](https://curl.haxx.se/libcurl/c/CURLOPT_FTPPORT.html) |TEXT|
[USERAGENT](https://curl.haxx.se/libcurl/c/CURLOPT_USERAGENT.html) |TEXT|
[LOW_SPEED_LIMIT](https://curl.haxx.se/libcurl/c/CURLOPT_LOW_SPEED_LIMIT.html) |LONGINT|
[LOW_SPEED_TIME](https://curl.haxx.se/libcurl/c/CURLOPT_LOW_SPEED_TIME.html) |LONGINT|
[RESUME_FROM](https://curl.haxx.se/libcurl/c/CURLOPT_RESUME_FROM.html) |LONGINT|
[COOKIE](https://curl.haxx.se/libcurl/c/CURLOPT_COOKIE.html) |TEXT|
[SSLCERT](https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERT.html) |TEXT|path
[KEYPASSWD](https://curl.haxx.se/libcurl/c/CURLOPT_KEYPASSWD.html) |TEXT|
[CRLF](https://curl.haxx.se/libcurl/c/CURLOPT_CRLF.html) |LONGINT|
[COOKIEFILE](https://curl.haxx.se/libcurl/c/CURLOPT_COOKIEFILE.html) |TEXT|path
[TIMEVALUE](https://curl.haxx.se/libcurl/c/CURLOPT_TIMEVALUE.html) |LONGINT|
[CUSTOMREQUEST](https://curl.haxx.se/libcurl/c/CURLOPT_CUSTOMREQUEST.html) |TEXT|
[HEADER](https://curl.haxx.se/libcurl/c/CURLOPT_HEADER.html) |LONGINT|
[NOBODY](https://curl.haxx.se/libcurl/c/CURLOPT_NOBODY.html) |LONGINT|
[FAILONERROR](https://curl.haxx.se/libcurl/c/CURLOPT_FAILONERROR.html) |LONGINT|
[UPLOAD](https://curl.haxx.se/libcurl/c/CURLOPT_UPLOAD.html) |LONGINT|
[POST](https://curl.haxx.se/libcurl/c/CURLOPT_POST.html) |LONGINT|
[DIRLISTONLY](https://curl.haxx.se/libcurl/c/CURLOPT_DIRLISTONLY.html) |LONGINT|
[APPEND](https://curl.haxx.se/libcurl/c/CURLOPT_APPEND.html) |LONGINT|
[NETRC](https://curl.haxx.se/libcurl/c/CURLOPT_NETRC.html) |LONGINT|
[FOLLOWLOCATION](https://curl.haxx.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html) |LONGINT|
[PUT](https://curl.haxx.se/libcurl/c/CURLOPT_PUT.html) |LONGINT|
[AUTOREFERER](https://curl.haxx.se/libcurl/c/CURLOPT_AUTOREFERER.html) |LONGINT|
[PROXYPORT](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYPORT.html) |LONGINT|
[HTTPPROXYTUNNEL](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPPROXYTUNNEL.html) |LONGINT|
[INTERFACE](https://curl.haxx.se/libcurl/c/CURLOPT_INTERFACE.html) |TEXT|
[KRBLEVEL](https://curl.haxx.se/libcurl/c/CURLOPT_KRBLEVEL.html) |TEXT|
[SSL_VERIFYPEER](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html) |LONGINT|
[CAINFO](https://curl.haxx.se/libcurl/c/CURLOPT_CAINFO.html) |TEXT|path
[MAXREDIRS](https://curl.haxx.se/libcurl/c/CURLOPT_MAXREDIRS.html) |LONGINT|
[FILETIME](https://curl.haxx.se/libcurl/c/CURLOPT_FILETIME.html) |LONGINT|
[MAXCONNECTS](https://curl.haxx.se/libcurl/c/CURLOPT_MAXCONNECTS.html) |LONGINT|
[FRESH_CONNECT](https://curl.haxx.se/libcurl/c/CURLOPT_FRESH_CONNECT.html) |LONGINT|
[FORBID_REUSE](https://curl.haxx.se/libcurl/c/CURLOPT_FORBID_REUSE.html) |LONGINT|
[RANDOM_FILE](https://curl.haxx.se/libcurl/c/CURLOPT_RANDOM_FILE.html) |TEXT|
[EGDSOCKET](https://curl.haxx.se/libcurl/c/CURLOPT_EGDSOCKET.html) |TEXT|
[CONNECTTIMEOUT](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html) |LONGINT|
[HTTPGET](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPGET.html) |LONGINT|
[SSL_VERIFYHOST](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html) |LONGINT|
[COOKIEJAR](https://curl.haxx.se/libcurl/c/CURLOPT_COOKIEJAR.html) |TEXT|path
[SSL_CIPHER_LIST](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_CIPHER_LIST.html) |TEXT|
[FTP_USE_EPSV](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_USE_EPSV.html) |LONGINT|
[SSLCERTTYPE](https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERTTYPE.html) |TEXT|
[SSLKEY](https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY.html) |TEXT|path
[SSLKEYTYPE](https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEYTYPE.html) |TEXT|
[DNS_CACHE_TIMEOUT](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_CACHE_TIMEOUT.html) |LONGINT|
[COOKIESESSION](https://curl.haxx.se/libcurl/c/CURLOPT_COOKIESESSION.html) |LONGINT|
[CAPATH](https://curl.haxx.se/libcurl/c/CURLOPT_CAPATH.html) |TEXT|path
[BUFFERSIZE](https://curl.haxx.se/libcurl/c/CURLOPT_BUFFERSIZE.html) |LONGINT|
[ACCEPT_ENCODING](https://curl.haxx.se/libcurl/c/CURLOPT_ACCEPT_ENCODING.html) |TEXT|
[UNRESTRICTED_AUTH](https://curl.haxx.se/libcurl/c/CURLOPT_UNRESTRICTED_AUTH.html) |LONGINT|
[FTP_USE_EPRT](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_USE_EPRT.html) |LONGINT|
[HTTPAUTH](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPAUTH.html) |LONGINT|
[FTP_CREATE_MISSING_DIRS](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_CREATE_MISSING_DIRS.html) |LONGINT|
[PROXYAUTH](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYAUTH.html) |LONGINT|
[FTP_RESPONSE_TIMEOUT](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_RESPONSE_TIMEOUT.html) |LONGINT|
[IPRESOLVE](https://curl.haxx.se/libcurl/c/CURLOPT_IPRESOLVE.html) |LONGINT|
[MAXFILESIZE](https://curl.haxx.se/libcurl/c/CURLOPT_MAXFILESIZE.html) |LONGINT|
[RESUME_FROM_LARGE](https://curl.haxx.se/libcurl/c/CURLOPT_RESUME_FROM_LARGE.html) |TEXT|text, to support 64-bit integer
[MAXFILESIZE_LARGE](https://curl.haxx.se/libcurl/c/CURLOPT_MAXFILESIZE_LARGE.html) |TEXT|text, to support 64-bit integer
[NETRC_FILE](https://curl.haxx.se/libcurl/c/CURLOPT_NETRC_FILE.html) |TEXT|path
[FTP_ACCOUNT](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_ACCOUNT.html) |TEXT|
[COOKIELIST](https://curl.haxx.se/libcurl/c/CURLOPT_COOKIELIST.html) |TEXT|
[IGNORE_CONTENT_LENGTH](https://curl.haxx.se/libcurl/c/CURLOPT_IGNORE_CONTENT_LENGTH.html) |LONGINT|
[FTP_SKIP_PASV_IP](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_SKIP_PASV_IP.html) |LONGINT|
[FTP_FILEMETHOD](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_FILEMETHOD.html) |LONGINT|
[LOCALPORT](https://curl.haxx.se/libcurl/c/CURLOPT_LOCALPORT.html) |LONGINT|
[LOCALPORTRANGE](https://curl.haxx.se/libcurl/c/CURLOPT_LOCALPORTRANGE.html) |LONGINT|
[CONNECT_ONLY](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECT_ONLY.html) |LONGINT|
[MAX_SEND_SPEED_LARGE](https://curl.haxx.se/libcurl/c/CURLOPT_MAX_SEND_SPEED_LARGE.html) |TEXT|text, to support 64-bit integer
[MAX_RECV_SPEED_LARGE](https://curl.haxx.se/libcurl/c/CURLOPT_MAX_RECV_SPEED_LARGE.html) |TEXT|text, to support 64-bit integer
[FTP_ALTERNATIVE_TO_USER](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_ALTERNATIVE_TO_USER.html) |TEXT|
[SSL_SESSIONID_CACHE](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_SESSIONID_CACHE.html) |LONGINT|
[SSH_AUTH_TYPES](https://curl.haxx.se/libcurl/c/CURLOPT_SSH_AUTH_TYPES.html) |LONGINT|
[SSH_PUBLIC_KEYFILE](https://curl.haxx.se/libcurl/c/CURLOPT_SSH_PUBLIC_KEYFILE.html) |TEXT|path
[SSH_PRIVATE_KEYFILE](https://curl.haxx.se/libcurl/c/CURLOPT_SSH_PRIVATE_KEYFILE.html) |TEXT|path
[FTP_SSL_CCC](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_SSL_CCC.html) |LONGINT|
[TIMEOUT_MS](https://curl.haxx.se/libcurl/c/CURLOPT_TIMEOUT_MS.html) |LONGINT|
[CONNECTTIMEOUT_MS](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT_MS.html) |LONGINT|
[HTTP_TRANSFER_DECODING](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_TRANSFER_DECODING.html) |LONGINT|
[HTTP_CONTENT_DECODING](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_CONTENT_DECODING.html) |LONGINT|
[NEW_FILE_PERMS](https://curl.haxx.se/libcurl/c/CURLOPT_NEW_FILE_PERMS.html) |LONGINT|
[NEW_DIRECTORY_PERMS](https://curl.haxx.se/libcurl/c/CURLOPT_NEW_DIRECTORY_PERMS.html) |LONGINT|
[POSTREDIR](https://curl.haxx.se/libcurl/c/CURLOPT_POSTREDIR.html) |LONGINT|
[SSH_HOST_PUBLIC_KEY_MD5](https://curl.haxx.se/libcurl/c/CURLOPT_SSH_HOST_PUBLIC_KEY_MD5.html) |TEXT|
[PROXY_TRANSFER_MODE](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_TRANSFER_MODE.html) |LONGINT|
[CRLFILE](https://curl.haxx.se/libcurl/c/CURLOPT_CRLFILE.html) |TEXT|path
[ISSUERCERT](https://curl.haxx.se/libcurl/c/CURLOPT_ISSUERCERT.html) |TEXT|path
[ADDRESS_SCOPE](https://curl.haxx.se/libcurl/c/CURLOPT_ADDRESS_SCOPE.html) |LONGINT|
[CERTINFO](https://curl.haxx.se/libcurl/c/CURLOPT_CERTINFO.html) |LONGINT|
[USERNAME](https://curl.haxx.se/libcurl/c/CURLOPT_USERNAME.html) |TEXT|
[PASSWORD](https://curl.haxx.se/libcurl/c/CURLOPT_PASSWORD.html) |TEXT|
[PROXYUSERNAME](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYUSERNAME.html) |TEXT|
[PROXYPASSWORD](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYPASSWORD.html) |TEXT|
[NOPROXY](https://curl.haxx.se/libcurl/c/CURLOPT_NOPROXY.html) |TEXT|
[TFTP_BLKSIZE](https://curl.haxx.se/libcurl/c/CURLOPT_TFTP_BLKSIZE.html) |LONGINT|
[PROTOCOLS](https://curl.haxx.se/libcurl/c/CURLOPT_PROTOCOLS.html) |LONGINT|
[REDIR_PROTOCOLS](https://curl.haxx.se/libcurl/c/CURLOPT_REDIR_PROTOCOLS.html) |LONGINT|
[SSH_KNOWNHOSTS](https://curl.haxx.se/libcurl/c/CURLOPT_SSH_KNOWNHOSTS.html) |TEXT|
[FTP_USE_PRET](https://curl.haxx.se/libcurl/c/CURLOPT_FTP_USE_PRET.html) |LONGINT|
[RTSP_REQUEST](https://curl.haxx.se/libcurl/c/CURLOPT_RTSP_REQUEST.html) |LONGINT|
[RTSP_SESSION_ID](https://curl.haxx.se/libcurl/c/CURLOPT_RTSP_SESSION_ID.html) |TEXT|
[RTSP_STREAM_URI](https://curl.haxx.se/libcurl/c/CURLOPT_RTSP_STREAM_URI.html) |TEXT|
[RTSP_TRANSPORT](https://curl.haxx.se/libcurl/c/CURLOPT_RTSP_TRANSPORT.html) |TEXT|
[RTSP_CLIENT_CSEQ](https://curl.haxx.se/libcurl/c/CURLOPT_RTSP_CLIENT_CSEQ.html) |LONGINT|
[RTSP_SERVER_CSEQ](https://curl.haxx.se/libcurl/c/CURLOPT_RTSP_SERVER_CSEQ.html) |LONGINT|
[WILDCARDMATCH](https://curl.haxx.se/libcurl/c/CURLOPT_WILDCARDMATCH.html) |LONGINT|
[TLSAUTH_USERNAME](https://curl.haxx.se/libcurl/c/CURLOPT_TLSAUTH_USERNAME.html) |TEXT|
[TLSAUTH_PASSWORD](https://curl.haxx.se/libcurl/c/CURLOPT_TLSAUTH_PASSWORD.html) |TEXT|
[TLSAUTH_TYPE](https://curl.haxx.se/libcurl/c/CURLOPT_TLSAUTH_TYPE.html) |TEXT|
[TRANSFER_ENCODING](https://curl.haxx.se/libcurl/c/CURLOPT_TRANSFER_ENCODING.html) |LONGINT|
[DNS_SERVERS](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_SERVERS.html) |TEXT|
[ACCEPTTIMEOUT_MS](https://curl.haxx.se/libcurl/c/CURLOPT_ACCEPTTIMEOUT_MS.html) |LONGINT|
[TCP_KEEPALIVE](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_KEEPALIVE.html) |LONGINT|
[TCP_KEEPIDLE](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_KEEPIDLE.html) |LONGINT|
[TCP_KEEPINTVL](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_KEEPINTVL.html) |LONGINT|
[MAIL_AUTH](https://curl.haxx.se/libcurl/c/CURLOPT_MAIL_AUTH.html) |TEXT|
[SASL_IR](https://curl.haxx.se/libcurl/c/CURLOPT_SASL_IR.html) |LONGINT|
[XOAUTH2_BEARER](https://curl.haxx.se/libcurl/c/CURLOPT_XOAUTH2_BEARER.html) |TEXT|
[DNS_INTERFACE](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_INTERFACE.html) |TEXT|
[DNS_LOCAL_IP4](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_LOCAL_IP4.html) |TEXT|
[DNS_LOCAL_IP6](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_LOCAL_IP6.html) |TEXT|
[LOGIN_OPTIONS](https://curl.haxx.se/libcurl/c/CURLOPT_LOGIN_OPTIONS.html) |TEXT|
[SSL_ENABLE_NPN](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_ENABLE_NPN.html) |LONGINT|
[SSL_ENABLE_ALPN](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_ENABLE_ALPN.html) |LONGINT|
[EXPECT_100_TIMEOUT_MS](https://curl.haxx.se/libcurl/c/CURLOPT_EXPECT_100_TIMEOUT_MS.html) |LONGINT|
[HEADEROPT](https://curl.haxx.se/libcurl/c/CURLOPT_HEADEROPT.html) |LONGINT|
[PINNEDPUBLICKEY](https://curl.haxx.se/libcurl/c/CURLOPT_PINNEDPUBLICKEY.html) |TEXT|path or value
[SSL_VERIFYSTATUS](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYSTATUS.html) |LONGINT|
[SSL_FALSESTART](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_FALSESTART.html) |LONGINT|
[PATH_AS_IS](https://curl.haxx.se/libcurl/c/CURLOPT_PATH_AS_IS.html) |LONGINT|
[PROXY_SERVICE_NAME](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SERVICE_NAME.html) |TEXT|
[SERVICE_NAME](https://curl.haxx.se/libcurl/c/CURLOPT_SERVICE_NAME.html) |TEXT|
[PIPEWAIT](https://curl.haxx.se/libcurl/c/CURLOPT_PIPEWAIT.html) |LONGINT|
[DEFAULT_PROTOCOL](https://curl.haxx.se/libcurl/c/CURLOPT_DEFAULT_PROTOCOL.html) |TEXT|
[STREAM_WEIGHT](https://curl.haxx.se/libcurl/c/CURLOPT_STREAM_WEIGHT.html) |LONGINT|
[TFTP_NO_OPTIONS](https://curl.haxx.se/libcurl/c/CURLOPT_TFTP_NO_OPTIONS.html) |LONGINT|
[TCP_FASTOPEN](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_FASTOPEN.html) |LONGINT|
[KEEP_SENDING_ON_ERROR](https://curl.haxx.se/libcurl/c/CURLOPT_KEEP_SENDING_ON_ERROR.html) |LONGINT|
[PROXY_CAINFO](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_CAINFO.html) |TEXT|path
[PROXY_CAPATH](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_CAPATH.html) |TEXT|path
[PROXY_SSL_VERIFYPEER](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSL_VERIFYPEER.html) |LONGINT|
[PROXY_SSL_VERIFYHOST](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSL_VERIFYHOST.html) |LONGINT|
[PROXY_TLSAUTH_USERNAME](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_TLSAUTH_USERNAME.html) |TEXT|
[PROXY_TLSAUTH_PASSWORD](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_TLSAUTH_PASSWORD.html) |TEXT|
[PROXY_TLSAUTH_TYPE](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_TLSAUTH_TYPE.html) |TEXT|
[PROXY_SSLCERT](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSLCERT.html) |TEXT|path
[PROXY_SSLCERTTYPE](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSLCERTTYPE.html) |TEXT|
[PROXY_SSLKEY](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSLKEY.html) |TEXT|path
[PROXY_SSLKEYTYPE](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSLKEYTYPE.html) |TEXT|
[PROXY_KEYPASSWD](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_KEYPASSWD.html) |TEXT|
[PROXY_SSL_CIPHER_LIST](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSL_CIPHER_LIST.html) |TEXT|
[PROXY_CRLFILE](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_CRLFILE.html) |TEXT|path
[PROXY_SSL_OPTIONS](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSL_OPTIONS.html) |LONGINT|
[PRE_PROXY](https://curl.haxx.se/libcurl/c/CURLOPT_PRE_PROXY.html) |TEXT|
[PROXY_PINNEDPUBLICKEY](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_PINNEDPUBLICKEY.html) |TEXT|
[SUPPRESS_CONNECT_HEADERS](https://curl.haxx.se/libcurl/c/CURLOPT_SUPPRESS_CONNECT_HEADERS.html) |LONGINT|
[REQUEST_TARGET](https://curl.haxx.se/libcurl/c/CURLOPT_REQUEST_TARGET.html) |TEXT|
[SOCKS5_AUTH](https://curl.haxx.se/libcurl/c/CURLOPT_SOCKS5_AUTH.html) |LONGINT|
[SSH_COMPRESSION](https://curl.haxx.se/libcurl/c/CURLOPT_SSH_COMPRESSION.html) |LONGINT|
[TIMEVALUE_LARGE](https://curl.haxx.se/libcurl/c/CURLOPT_TIMEVALUE_LARGE.html) |TEXT|64-bit integer
[HAPPY_EYEBALLS_TIMEOUT_MS](https://curl.haxx.se/libcurl/c/CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS.html) |LONGINT|
[HAPROXYPROTOCOL](https://curl.haxx.se/libcurl/c/CURLOPT_HAPROXYPROTOCOL.html) |LONGINT|
[DNS_SHUFFLE_ADDRESSES](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_SHUFFLE_ADDRESSES.html) |LONGINT|
[TLS13_CIPHERS](https://curl.haxx.se/libcurl/c/CURLOPT_TLS13_CIPHERS.html) |TEXT|
[PROXY_TLS13_CIPHERS](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_TLS13_CIPHERS.html) |TEXT|
[DISALLOW_USERNAME_IN_URL](https://curl.haxx.se/libcurl/c/CURLOPT_DISALLOW_USERNAME_IN_URL.html) |LONGINT|
[DOH_URL](https://curl.haxx.se/libcurl/c/CURLOPT_DOH_URL.html) |TEXT|
[UPLOAD_BUFFERSIZE](https://curl.haxx.se/libcurl/c/CURLOPT_UPLOAD_BUFFERSIZE.html) |LONGINT|
[UPKEEP_INTERVAL_MS](https://curl.haxx.se/libcurl/c/CURLOPT_UPKEEP_INTERVAL_MS.html) |LONGINT|

---

Standard  ``options`` with constant support

Value|Type|Description
------------|------------|----
[USE_SSL](https://curl.haxx.se/libcurl/c/CURLOPT_USE_SSL.html) |TEXT|USESSL_NONE, USESSL_TRY, USESSL_CONTROL, USESSL_ALL
[SSLVERSION](https://curl.haxx.se/libcurl/c/CURLOPT_SSLVERSION.html) |TEXT|SSLVERSION_TLSv1, SSLVERSION_SSLv2, SSLVERSION_SSLv3, SSLVERSION_TLSv1_0, SSLVERSION_TLSv1_1, SSLVERSION_TLSv1_2, SSLVERSION_TLSv1_3
[HTTP_VERSION](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_VERSION.html) |TEXT|HTTP_VERSION_1_0, HTTP_VERSION_1_1, HTTP_VERSION_2_0, HTTP_VERSION_2TLS, HTTP_VERSION_2_PRIOR_KNOWLEDGE
[PROXY_SSLVERSION](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY_SSLVERSION.html) |TEXT|SSLVERSION_TLSv1, SSLVERSION_SSLv2, SSLVERSION_SSLv3, SSLVERSION_TLSv1_0, SSLVERSION_TLSv1_1, SSLVERSION_TLSv1_2, SSLVERSION_TLSv1_3
[TIMECONDITION](https://curl.haxx.se/libcurl/c/CURLOPT_TIMECONDITION.html) |TEXT|TIMECOND_IFMODSINCE, TIMECOND_IFUNMODSINCE, TIMECOND_LASTMOD
[PROXYTYPE](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYTYPE.html) |TEXT|PROXY_HTTPS, PROXY_SOCKS4, PROXY_SOCKS4A, PROXY_SOCKS5
[FTPSSLAUTH](https://curl.haxx.se/libcurl/c/CURLOPT_FTPSSLAUTH.html) |TEXT|FTPAUTH_SSL, FTPAUTH_TLS
[HEADEROPT](https://curl.haxx.se/libcurl/c/CURLOPT_HEADEROPT.html) |TEXT|HEADER_UNIFIED, HEADER_SEPARATE

---

Standard  ``options`` with collection support

Value|Type|Description
------------|------------|----
[CONNECT_TO](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECT_TO.html) |COLLECTION|text array
[PROXYHEADER](https://curl.haxx.se/libcurl/c/CURLOPT_PROXYHEADER.html) |COLLECTION|text array
[HTTPHEADER](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPHEADER.html) |COLLECTION|text array
[HTTP200ALIASES](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP200ALIASES.html) |COLLECTION|text array
[RESOLVE](https://curl.haxx.se/libcurl/c/CURLOPT_RESOLVE.html) |COLLECTION|text array
[MAIL_RCPT](https://curl.haxx.se/libcurl/c/CURLOPT_MAIL_RCPT.html) |COLLECTION|text array
[MAIL_FROM](https://curl.haxx.se/libcurl/c/CURLOPT_MAIL_FROM.html) |TEXT|
[PREQUOTE](https://curl.haxx.se/libcurl/c/CURLOPT_PREQUOTE.html) |COLLECTION|text array
[POSTQUOTE](https://curl.haxx.se/libcurl/c/CURLOPT_POSTQUOTE.html) |COLLECTION|text array
[QUOTE](https://curl.haxx.se/libcurl/c/CURLOPT_QUOTE.html) |COLLECTION|text array
[TELNETOPTIONS](https://curl.haxx.se/libcurl/c/CURLOPT_TELNETOPTIONS.html) |COLLECTION|text array

---

Not supported

``POSTFIELDSIZE_LARGE`` (automatic)  
``INFILESIZE_LARGE`` (automatic)  
``POSTFIELDS``  
``VERBOSE``  
``NOPROGRESS``  
``READFUNCTION``  
``WRITEFUNCTION``  
``ERRORBUFFER``  
``READDATA``  
``WRITEDATA``  
``OBSOLETE72``  
``PROGRESSDATA``  
``PROGRESSFUNCTION``  
``TRANSFERTEXT``  
``OBSOLETE40``  
``STDERR``  
``HEADERDATA``  
``HTTPPOST``  
``IOCTLDATA``  
``IOCTLFUNCTION``  
``TCP_NODELAY``  
``SSL_CTX_DATA``  
``SSL_CTX_FUNCTION``  
``SHARE``  
``NOSIGNAL``  
``DEBUGDATA``  
``DEBUGFUNCTION``  
``DNS_USE_GLOBAL_CACHE``  
``SSLENGINE_DEFAULT``  
``SSLENGINE``  
``HEADERFUNCTION``  
``SEEKDATA``  
``SEEKFUNCTION``  
``COPYPOSTFIELDS``  
``OPENSOCKETDATA``  
``OPENSOCKETFUNCTION``  
``SOCKOPTDATA``  
``SOCKOPTFUNCTION``  
``CONV_FROM_UTF8_FUNCTION``  
``CONV_TO_NETWORK_FUNCTION``  
``CONV_FROM_NETWORK_FUNCTION``  
``GSSAPI_DELEGATION``  
``SOCKS5_GSSAPI_NEC``  
``SOCKS5_GSSAPI_SERVICE``  
``CLOSESOCKETDATA``  
``CLOSESOCKETFUNCTION``  
``FNMATCH_DATA``  
``CHUNK_DATA``  
``FNMATCH_FUNCTION``  
``CHUNK_END_FUNCTION``  
``CHUNK_BGN_FUNCTION``  
``INTERLEAVEFUNCTION``  
``INTERLEAVEDATA``  
``SSH_KEYDATA``  
``SSH_KEYFUNCTION``  
``STREAM_DEPENDS_E``  
``STREAM_DEPENDS``  
``UNIX_SOCKET_PATH``  
``XFERINFOFUNCTION``  
``SSL_OPTIONS``  
``ABSTRACT_UNIX_SOCKET``  
``MIMEPOST``  
``RESOLVER_START_FUNCTION``  
``RESOLVER_START_DATA``  

---

### Tips

* SMTP

You might want to enable ``FORBID_REUSE`` if your plan is to use different credentials in a batch process. By default, cURL re-uses the TCP connection, which may not be what you want.

You can pass a collection or string to ``MAIL_TO``. But you can only pass string to ``MAIL_FROM``.

You must pass a simple email adress to ``MAIL_FROM``. You can NOT pass the email address with a display name, as you would do for the SMTP header. (It is your responsibility to include a well-formatted ``From`` header in the SMTP request.

* Any

By default, cURL has a very tolerant timeout setting. In production, you might want to explicitly set all the timeout options.

