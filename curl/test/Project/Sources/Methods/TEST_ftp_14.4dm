//%attributes = {}
C_OBJECT:C1216($options)

OB SET:C1220($options; "URL"; $vt_remote)
$options.SSL_VERIFYPEER:=0
$options.SSL_VERIFYHOST:=0
$options.UPLOAD:=1
$options.USERNAME:="tester"
$options.PASSWORD:="password"

SET BLOB SIZE:C606($request; 0)
SET BLOB SIZE:C606($response; 0)
DOCUMENT TO BLOB:C525($path; $request)

$error:=cURL($options; $request; $response; ""; $transferInfo; $headerInfo)

