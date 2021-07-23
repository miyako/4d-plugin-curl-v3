//%attributes = {}
$options:=New object:C1471
$options.URL:="ftps://tsftp.4d.com/testxxxx"
$options.USERNAME:=""
$options.PASSWORD:=""
$options.SSL_VERIFYHOST:=0
$options.SSL_VERIFYPEER:=0
$status:=cURL_FTP_MakeDir ($options;"")
