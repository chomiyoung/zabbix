<?php 

$url = 'http://121.78.95.241/api_jsonrpc.php'; 
$header = array("Content-type: application/json-rpc"); 
  

 function Curl($url,$header,$info){ 
     $ch = curl_init(); 
     curl_setopt($ch,CURLOPT_URL, $url); 
     curl_setopt($ch,CURLOPT_RETURNTRANSFER, 1); 
     curl_setopt($ch,CURLOPT_HTTPHEADER,$header); 
     curl_setopt($ch,CURLOPT_POST, 1); 
     curl_setopt($ch,CURLOPT_POSTFIELDS, $info); 
     $response = curl_exec($ch); 
     curl_close($ch); 
     return json_decode($response); 
 } 
  
 $logininfo = '{"jsonrpc": "2.0","method":"user.login","params":{"user":"Admin","password":"zabbix"},"auth": null,"id":0}'; 
 $result = Curl($url,$header,$logininfo); 
 $token = $result->result; 
  
  
 $hostinfo = array( 
     'jsonrpc' => '2.0', 
     'method' => 'host.get', 
     "params" =>array( 
          "output" => ["hostid","name"],
          "selectGroups" => ("extend"),
          "filter" => array("groupid" =>"",) 
         ), 
     "auth"=>$token, 
     "id"=>1 
 ); 
$data = json_encode($hostinfo); 
$result = Curl($url,$header,$data);

print_r($result);

/*--
$hostlist=($result->result);

foreach ($result->result as $row){

	//echo "\n";
	echo "host: $row->name, ";

	foreach($row->groups as $row1){

		echo "group: $row1->name, ";
	
	}

	echo "\n";

}


//$hostlist=json_encode($result);
--*/
