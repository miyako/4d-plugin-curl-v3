//%attributes = {}
C_OBJECT:C1216($vObj_Options;$vObj_Result)
C_BLOB:C604($vx_Request;$vx_Response)
C_TEXT:C284($vT_callback)
$vObj_Options:=New object:C1471
$vObj_Options.URL:="https://www.apple.com/test"

$vObj_Options.DEBUG:=Get 4D folder:C485(Logs folder:K5:19)
If (Application type:C494#4D Server:K5:6)
	SHOW ON DISK:C922(Get 4D folder:C485(Logs folder:K5:19);*)
End if 

$vT_callback:=""
$vObj_Result:=cURL ($vObj_Options;$vx_Request;$vx_Response;$vT_callback)
