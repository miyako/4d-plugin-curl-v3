* `cURL_VersionInfo` on macOS

```json
{
	"version": "7.75.0",
	"version_num": 477952,
	"host": "x86_64-apple-darwin19.6.0",
	"features": 95012509,
	"ssl_version": "OpenSSL/1.1.1g",
	"libz_version": "1.2.11",
	"protocols": [
		"dict",
		"file",
		"ftp",
		"ftps",
		"gopher",
		"gophers",
		"http",
		"https",
		"imap",
		"imaps",
		"ldap",
		"ldaps",
		"mqtt",
		"pop3",
		"pop3s",
		"rtsp",
		"scp",
		"sftp",
		"smb",
		"smbs",
		"smtp",
		"smtps",
		"telnet",
		"tftp"
	],
	"libidn": "2.3.0",
	"libssh_version": "libssh2/1.9.0",
	"brotli_version": "1.0.9",
	"nghttp2_version": "1.43.0",
	"zstd_version": "1.4.9"
}
```

* `cURL_VersionInfo` on Windows

```json
{
	"version": "7.74.0-DEV",
	"version_num": 477696,
	"host": "Windows",
	"features": 23407517,
	"ssl_version": "OpenSSL/1.1.1j (Schannel)",
	"libz_version": "1.2.11",
	"protocols": [
		"dict",
		"file",
		"ftp",
		"ftps",
		"gopher",
		"http",
		"https",
		"imap",
		"imaps",
		"ldap",
		"mqtt",
		"pop3",
		"pop3s",
		"rtsp",
		"scp",
		"sftp",
		"smb",
		"smbs",
		"smtp",
		"smtps",
		"telnet",
		"tftp"
	],
	"libssh_version": "libssh2/1.9.0_DEV",
	"nghttp2_version": "1.42.0"
}
```

missing `zstd` `idn2` `brotli`, different `OpenSSL` `ssh2`

[vcpkg package features](https://vcpkg.info/port/curl):

``curl[brotli,c-ares,core,http2,non-http,openssl,schannel,ssh,ssl,sspi,winssl]:windows-static``

(static `idn2` is failing; library does not export symbols)
