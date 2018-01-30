#!/usr/bin/php
<?php
function HandleAttribute($attribute, $name, $out){
	$attribute = preg_replace("/[(,)]/", " ", $attribute);
	$attribute = preg_replace("/\s+/", " ", $attribute);
	$args = preg_split("/\s/", $attribute);
	switch(strtolower($args[0])){
		case "RelativeOffset":
			break;
		case "DllOffset":
			break;
	}
}

function ParseStmt($stmt){
	//printf("%s\n", $stmt);
	$parts = preg_split("/\s/", $stmt);
	//$ret_type = $parts[0];
	if(count($parts) < 2)
		return;

	$name = $parts[1];
	$len = strlen($name);
	if($len <= 0)
		return $name;
	
	if($name[$len-1] == ';')
		$name = substr($name, 0, $len-1);
	
	while(strlen($name) > 0 && $name[0] == '*')
		$name = substr($name, 1);
	
	$test = preg_replace("/\s/", "", $name);
	if(preg_match("/\(\*(.*?)\)/", $name, $m)){
		$name = $m[1];
	}

	return trim($name);
}

if($argc < 2){
	fprintf(STDERR, "Usage: %s [api-spec.h]\n", $argv[0]);
	return 1;
}

$spec = fopen($argv[1], "r") or die("Cannot open {$argv[1]} for reading\n");
$out = fopen($argv[2], "w+") or die("Cannot open {$argv[2]} for writing\n");

$bfile = basename($argv[1]);
$dirName = basename(__DIR__);

fwrite($out, '/****** THIS FILE HAS BEEN AUTOMATICALLY GENERATED. DON\'T EDIT ******/' . PHP_EOL);
fwrite($out, sprintf('#include "%s/%s"', $dirName, basename($argv[1])) . PHP_EOL);
fwrite($out, sprintf('%s_T hCTX = {{', pathinfo($bfile, PATHINFO_FILENAME)) . PHP_EOL);

$chars = "";
$begin = false;

$shouldSkip = false;
while(!feof($spec)){
	$ch = fgetc($spec);
	$chars .= $ch;

	$hasStruct = strpos($chars, "struct") !== FALSE;
	$hasExtern = strpos($chars, "extern") !== FALSE;
	if(!$begin && $hasStruct){
		$begin = true;
	}

	if($hasExtern){
		$shouldSkip = true;
	}

	if($ch == '{' || $ch == '}')
		$chars = ""; //erase buffer

	if($ch == ';' && $begin == true){
		if($shouldSkip){
			$shouldSkip = false;
			continue;
		}

		$attribute = null;
		if(preg_match("/\/\/\[(.*?)\]/", $chars, $m)){
			$attribute = trim($m[1]);
		}

		//remove defines
		$chars = preg_replace("/\#.*/", "", $chars);
		//remove comments
		$chars = preg_replace("/\/\/.*/", "", $chars);
		$chars = preg_replace("/\/\*.*\*\//", "", $chars);
		//remove curly braces
		$chars = preg_replace("/[{}]/", "", $chars);
		$chars = trim($chars);
		if(empty($chars))
			continue;

		$name = ParseStmt($chars);
		if(!empty($name)){
			//If an attribute is found, don't auto-resolve this symbol
			if(!is_null($attribute)){
				//HandleAttribute($attribute, $name, $out);
				fwrite($out, "\tNULL," . PHP_EOL);
			} else {
				fwrite($out, sprintf("\t\"%s\",", $name) . PHP_EOL);
			}
		}
		
		$chars = "";
	}
}

fclose($spec);

fseek($out, -2, SEEK_CUR);
fwrite($out, PHP_EOL . '}};' . PHP_EOL);
fclose($out);
return 0;
?>