<?php 
// Load the POST.
$data = file_get_contents("php://input");

// removes any weird characters
//--
$data = json_decode($data); 
$data = json_encode($data);
//--

// execute the script, give json file as variable
$name = shell_exec("whoami");
$command ="python3 /home/".trim($name)."/Desktop/Python/main3.py $data";
$result = exec($command);

// results are stored here
$result = strval($result);




// look at results to know the right status code to send back
if(strpos($result,'500') !== false)
{
http_response_code(500);
header('HTTP/1.1 500 Internal Server Error');
}
elseif(strpos($result,'200') !== false)
{
http_response_code(200);
header('HTTP/1.1 200 OK');
}
elseif(strpos($result,'501') !== false)
{
http_response_code(501);
header('HTTP/1.1 501 Not Implemented');
}
else{
http_response_code(500);
header('HTTP/1.1 500 Internal Server Error');
}


// make header information conform to standard
// important to note apache does have headers that can not be removed
header('Content-Type: application/openc2-rsp+json;version=1.0');
$RequestID = $_SERVER['HTTP_X_REQUEST_ID'];
header('X-Request-ID: '.$RequestID);

// return results back to our sendCommand file
echo($result);
