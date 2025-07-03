//%attributes = {}
$URL:="ftp://test.rebex.net/test"

C_OBJECT:C1216($options)
OB SET:C1220($options; "URL"; $URL)
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0
$options.USE_SSL:="USESSL_ALL"
$options.DEBUG:=System folder:C487(Desktop:K41:16)
$options.USERNAME:="demo"
$options.PASSWORD:="password"
$options.UPLOAD:=1

$file:=Folder:C1567(fk desktop folder:K87:19).file("test.txt")
$file.setText("TEST")
$options.READDATA:=$file.platformPath

C_BLOB:C604($request; $response)

$error:=cURL($options; $request; $response; "")

