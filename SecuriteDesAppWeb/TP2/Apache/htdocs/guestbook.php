<?php 
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; connect-src 'self' http://localhost:8080;");
$file="messages.txt";
$messages=file_get_contents($file);
 ?>
<html>
<head>
</head>
<body>
<h1>Welcome to our Guest Book, Leave us a Message! </h1>
<input  id="message" >
<button id="leaveMessage">Leave a message</button>
<h2>All the messages left by guests </h2>
<div id="show"><?php echo $messages?> </div>
<script src="scriptgustbook.js"></script>

</body>
</html>
