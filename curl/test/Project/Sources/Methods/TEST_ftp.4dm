//%attributes = {}
C_TEXT:C284($FTP_DL; $FTP)
C_OBJECT:C1216($INPUT; $OUTPUT)
C_BLOB:C604($BLOB)

$FTP_DL:=Temporary folder:C486+"help.zip"
$FTP:="ftp://download.dataline.eu/pub/documents/multipress/help/help53.zip"
OB SET:C1220($INPUT; "URL"; $FTP; "USERNAME"; ""; "PASSWORD"; ""; "WRITEDATA"; $FTP_DL)
$OUTPUT:=cURL_FTP_Receive($INPUT; $BLOB)
If ($OUTPUT.status=0)
	
End if 