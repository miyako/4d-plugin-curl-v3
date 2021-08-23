//%attributes = {}
/*

stfp on windows

*/


C_OBJECT:C1216($options;$status)

$options:=New object:C1471
$options.USERNAME:="miyako"
$options.SSH_AUTH_TYPES:=1  //CURLSSH_AUTH_PUBLICKEY
$options.KEYPASSWD:="pass"
$options.SSH_PRIVATE_KEYFILE:=Folder:C1567(fk desktop folder:K87:19).file("id_rsa").platformPath
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0

$options.URL:="sftp://100.64.1.57/Users/miyako/Desktop/uploaded.zip"

C_BLOB:C604($request;$reponse)

$status:=cURL ($options;$request;$reponse)
