//%attributes = {}
/*

cURL_FTP_MakeDir, cURL_FTP_Delete (FTPS)

*/

C_OBJECT:C1216($options;$status)

$options:=New object:C1471
$options.USERNAME:=""
$options.PASSWORD:=""
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0
$options.USE_SSL:="USESSL_ALL"

$options.URL:="ftps://.../test/upload.zip"

$status:=cURL_FTP_Delete ($options)

$options.URL:="ftps://tsftp.4d.com/test/"

$status:=cURL_FTP_RemoveDir ($options)