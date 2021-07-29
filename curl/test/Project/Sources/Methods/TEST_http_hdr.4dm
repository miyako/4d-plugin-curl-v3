//%attributes = {}
$options:=New object:C1471
$options.URL:="http://localhost/testxxxx"
$options.USERNAME:=""
$options.PASSWORD:=""
$options.HTTPHEADER:=New collection:C1472("accept: application/json";"pageLimit: 10";"pageCurrent: 1";"Authorization: Basic YXBpLmRvc2dyb3VwQGRvcy1nc206UGhhbGNvbjE1")

C_BLOB:C604($request;$reponse)

$status:=cURL ($options;$request;$reponse)

