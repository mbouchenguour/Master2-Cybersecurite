<?php 

echo "HTML entitities"; 

echo implode( "\t", array_values( get_html_translation_table( HTML_ENTITIES ) ) );

/* echo "'";*/
 
echo "<br> HTML Special Chars: <br>";

echo implode( "\t", array_values( get_html_translation_table( HTML_SPECIALCHARS ) ) );


?>
