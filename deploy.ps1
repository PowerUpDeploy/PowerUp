properties{
	$packageFolder = Get-Location
}


task default -depends importmodules, deployfiles, recreatesite

task importmodules {
	Import-Module PowerUpFileSystem
	Import-Module PowerUpWeb
}

task deployfiles {
	copy-mirroreddirectory $packageFolder\${package.name} ${deployment.root}\${package.name} 
}

task recreatesite {
	set-webapppool "simplewebsite" "Integrated" "v4.0"
	set-website "simplewebsite" "simplewebsite" ${deployment.root}\${package.name} "" "http" "*" 9000 	
	new-websitebinding "simplewebsite" "www.sample.com"
	set-selfsignedsslcertificate "simplewebsite"
	set-sslbinding "simplewebsite" "123.123.123.123" 9000
	new-websitebinding "simplewebsite" "sample.com"  "https" "123.123.123.123" 9000
}