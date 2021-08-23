//%attributes = {}
/*

cURL_FTP_Delete,cURL_FTP_RemoveDir (SFTP)

*/

C_OBJECT:C1216($options;$status)

$options:=New object:C1471
$options.USERNAME:="miyako"
$options.FTP_CREATE_MISSING_DIRS:=1
$options.SSH_AUTH_TYPES:=1  //CURLSSH_AUTH_PUBLICKEY
$options.KEYPASSWD:="pass"
$options.SSH_PRIVATE_KEYFILE:=Folder:C1567(fk desktop folder:K87:19).file("id_rsa").platformPath
$options.URL:="sftp://100.64.1.57/Users/miyako/Desktop/test/"

$status:=cURL_FTP_RemoveDir ($options)  //folder must be empty
