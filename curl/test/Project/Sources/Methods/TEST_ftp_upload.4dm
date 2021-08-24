//%attributes = {}
$file:=Folder:C1567(fk desktop folder:K87:19).file("vcpkg-master.zip")

$options:=New object:C1471
$options.URL:="sftp://.../"+$file.name+$file.extension
$options.UPLOAD:=1
$options.USERNAME:=""
$options.PASSWORD:=""
$options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert-2021-01-19.pem").platformPath
$options.BUFFERSIZE:=2000000
$options.READDATA:=$file.platformPath

/*
 1:CURLSSH_AUTH_PUBLICKEY
 2:CURLSSH_AUTH_PASSWORD
 4:CURLSSH_AUTH_HOST
 8:CURLSSH_AUTH_KEYBOARD (disabled)
16:CURLSSH_AUTH_AGENT (disabled)
32:CURLSSH_AUTH_GSSAPI
*/

C_BLOB:C604($request;$response)

$vt_callback:=""
$ob_status:=cURL ($options;$request;$response;$vt_callback)  //fail?
$ob_status:=cURL_FTP_Send ($options;$request;$vt_callback)  //success!
$ob_status:=cURL ($options;$request;$response;$vt_callback)  //success too!