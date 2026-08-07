//%attributes = {}
$vt_remote:="sftp://localhost:2222/Test.pdf"

C_OBJECT:C1216($options)
OB SET:C1220($options; "URL"; $vt_remote)
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0
$options.UPLOAD:=1
$options.USERNAME:="tester"
$options.PASSWORD:="password"

C_BLOB:C604($request; $response)

$error:=cURL($options; $request; $response; "")

