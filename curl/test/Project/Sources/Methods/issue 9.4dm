//%attributes = {}
/*

we need SFTP transfer with public key authentication
whatever I try, I can't get it working
on macOS the result is always (status=67)
on Windows the operation times out (status=28)

*/

C_OBJECT:C1216($options;$status)

$options:=New object:C1471
$options.USERNAME:="miyako"
$options.READDATA:=Folder:C1567(fk resources folder:K87:11).file("upload.zip").platformPath
$options.FTP_CREATE_MISSING_DIRS:=1
$options.SSH_AUTH_TYPES:=1  //CURLSSH_AUTH_PUBLICKEY
$options.UPLOAD:=1

/*

make sure id_rsa and id_rsa.pub have appropriate permissions
c.f. 
"WARNING: UNPROTECTED PRIVATE KEY FILE!"
Permissions 0644 for 'id_rsa.pub' are too open.
This private key will be ignored.

*/

If (True:C214)
	$options.KEYPASSWD:="pass"
	$options.SSH_PRIVATE_KEYFILE:=Folder:C1567(fk desktop folder:K87:19).file("id_rsa").platformPath
Else 
	  //this seems to result in error 67
	$options.SSH_PUBLIC_KEYFILE:=Folder:C1567(fk desktop folder:K87:19).file("id_rsa.pub").platformPath
End if 

$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0

$options.URL:="sftp://100.64.1.57/Users/miyako/Desktop/uploaded.zip"

$status:=cURL_FTP_Send ($options)