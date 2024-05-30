//%attributes = {}
var $options; $status : Object
var $request; $response : Blob
var $callback : Text

$options:=New object:C1471
$options.URL:="https://www.apple.com/"
$options.CERTINFO:=1
$options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert-2021-01-19.pem").platformPath

$status:=cURL($options; $request; $response)

