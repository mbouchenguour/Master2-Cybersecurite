Java.perform(function () {
    // Classe de détection root
    var RootDetection = Java.use("sg.vantagepoint.a.c");

    RootDetection.a.implementation = function () {
        console.log("RootDetection.a() intercepted!");
        return false; // Forcer false
    };

    RootDetection.b.implementation = function () {
        console.log("RootDetection.b() intercepted!");
        return false; // Forcer false
    };

    RootDetection.c.implementation = function () {
        console.log("RootDetection.c() intercepted!");
        return false; // Forcer false
    };

    console.log("Root detection hooks applied.");

    // Classe de détection debug
    var DebugDetection = Java.use("sg.vantagepoint.a.b");

    DebugDetection.a.implementation = function (context) {
        console.log("DebugDetection.a() intercepted!");
        return false; // Forcer false
    };

    console.log("Debug detection hook applied.");

    Java.perform(function () {
        console.log("Hooking AES decryption...");
    
        var AES = Java.use("sg.vantagepoint.a.a");
    
        AES.a.overload("[B", "[B").implementation = function (key, data) {
            console.log("Key: " + bytesToString(key));
            console.log("Data: " + bytesToString(data));
    
            var result = this.a(key, data); // Appeler l'implémentation originale
    
            console.log("Decrypted result: " + bytesToString(result));
            return result;
        };
    
        function bytesToString(byteArray) {
            var result = "";
            for (var i = 0; i < byteArray.length; i++) {
                result += String.fromCharCode(byteArray[i]);
            }
            return result;
        }
    
        console.log("Hook applied to AES decryption.");
    });

    
});
