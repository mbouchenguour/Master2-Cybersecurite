<?php
//header("Content-Security-Policy: script-src 'self'");
?>
<html>
<head></head>
<body>
<h1> XSS me</h1>

<p> XSS me in a HTML context with $_GET[htmlcontext] <br> </p>
<p>
<?php 
    echo htmlspecialchars($_GET['htmlcontext']);
?> 
</p>

<p> XSS me in an attribute context without quotes with  $_GET[attributecontext1] and with double quotes with  $_GET[attributecontext2] and with single quotes with   $_GET[attributecontext3] </p>    

    <img src = "<?php echo htmlspecialchars($_GET['attributecontext1'], ENT_QUOTES)?> ">
    <img src =" <?php echo htmlspecialchars($_GET['attributecontext2'], ENT_QUOTES)?> ">
    <img src =' <?php echo htmlspecialchars($_GET['attributecontext3'], ENT_QUOTES)?> '>

<p> XSS me inside a script  context with  $_GET[scriptcontext] 
 <script> 
    x = <?php echo json_encode($_GET['scriptcontext'], JSON_HEX_TAG); ?>;
	function foo(){alert(1)};
      console.log(x);  
  </script>

<p> XSS me inside an onerror attribute  context with  $_GET[attributecontextonerror] </P> 

    <img src =1  onerror="<?php echo htmlspecialchars($_GET['attributecontextonerror'], ENT_QUOTES)?>" >

</body> 
 

</html>
