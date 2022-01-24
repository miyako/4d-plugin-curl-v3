//%attributes = {}
/*

added ftparse

*/

C_OBJECT:C1216($options; $status)

$options:=New object:C1471
$options.USERNAME:=""
$options.PASSWORD:=""
$options.URL:=""

$status:=cURL_FTP_GetDirList($options)  //folder must be empty
