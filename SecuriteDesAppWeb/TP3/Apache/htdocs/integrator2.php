<?php header("Content-Security-Policy: script-src 'self'"); ?>
<html>

<h1>
Trusted page

<div id=secret>
42
</div>
</h1>

<script src=http://localhost:9999/evilGadget.js></script>

</html>