//%attributes = {}
var $options; $status : Object
var $request; $response : Blob
var $callback : Text

$options:=New object:C1471
$options.URL:=""
$options.USERNAME:=""
$options.PASSWORD:=""

$options.FTP_USE_MLSD:=True:C214  //send MLSD insteand of LIST

$status:=cURL_FTP_GetDirList($options)