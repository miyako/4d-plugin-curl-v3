//%attributes = {}
/*

to avoid error 60, use cacert.pem from https://curl.se/docs/caextract.html

*/

$options:=New object:C1471
$options.URL:="http://download.4d.com/Products/Archives/Line_v11/11_9/Mac/DMGs/4D_v11_SQL_Release_9_US.dmg"
$options.PRIVATE:="blar blar blar"  //pass as $2 to callback 
$options.CAINFO:=Folder:C1567(fk resources folder:K87:11).file("cacert-2021-01-19.pem").platformPath
$options.BUFFERSIZE:=2000000
$options.WRITEDATA:=Folder:C1567(fk desktop folder:K87:19).file("test.test").platformPath
$options.FOLLOWLOCATION:=1
$options.MAXREDIRS:=10

$callback:="TEST_PROGRESS"

C_BLOB:C604($request;$reponse)

$status:=cURL ($options;$request;$reponse;$callback)