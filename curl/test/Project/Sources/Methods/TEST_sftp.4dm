//%attributes = {}
C_OBJECT:C1216($options;$status)

$options:=New object:C1471
$options.USERNAME:="miyako"
$options.SSH_AUTH_TYPES:=1  //CURLSSH_AUTH_PUBLICKEY
$options.KEYPASSWD:="pass"
$options.SSH_PRIVATE_KEYFILE:=Folder:C1567(fk desktop folder:K87:19).file("id_rsa").platformPath
$options.FTP_CREATE_MISSING_DIRS:=1
$options.READDATA:=Folder:C1567(fk resources folder:K87:11).file("upload.zip").platformPath

/*

tips: 

* don't pass SSH_PUBLIC_KEYFILE

* don't pass PASSWORD when connecting with public key authentication

* all paths are platform, not POSIX

* on Mac, make sure make sure id_rsa has appropriate permissions 
  Google: Permissions 0644 for 'id_rsa' are too open.

* SSL_VERIFYPEER, SSL_VERIFYHOST are not necessary 

*/

$options.URL:="sftp://100.64.1.57/Users/miyako/Desktop/uploaded.zip"

If (False:C215)
	
	  //generic cURL
	
	C_BLOB:C604($request;$response)
	$options.UPLOAD:=1
	$status:=cURL ($options;$request;$response)
	
Else 
	
	  //FTP high level command
	
	$status:=cURL_FTP_Send ($options)
	
End if 