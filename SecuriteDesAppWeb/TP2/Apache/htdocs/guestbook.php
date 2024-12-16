<?php 
header("Content-Security-Policy: script-src 'self'");
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
