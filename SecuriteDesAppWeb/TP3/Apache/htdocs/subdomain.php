<?php
$domainName = 'host.com';
    $subDomainName =  'subdomain';
     $subDomain = $subDomainName;
    $rootDomain = $domainName;
    
    $buildRequest = "/frontend/paper_lantern/subdomain/doadddomain.html?rootdomain=" . $rootDomain . "&domain=" . $subDomain . "&dir=public_html/$domainName/$subDomain";
      
     
    echo $newDomain = "http://" . $subDomain . "." . $rootDomain . "/";
?>

