![version](https://img.shields.io/badge/version-17%2B-3E8B93)
![platform](https://img.shields.io/static/v1?label=platform&message=mac-intel%20|%20mac-arm%20|%20win-64&color=blue)
[![license](https://img.shields.io/github/license/miyako/4d-plugin-curl-v3)](LICENSE)
![downloads](https://img.shields.io/github/downloads/miyako/4d-plugin-curl-v3/total)

# 4d-plugin-curl-v3
Generic network client based on libcurl.

#### changes since v2

* macOS library version update: from `libcurl-7.62.0` to `libcurl-7.75.0` 

* Windows library version update: from `libcurl-7.62.0` to `libcurl-7.74.0-DEV`

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
