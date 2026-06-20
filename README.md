# AutoIt to PHP Secure Communication (3DES)

This project provides a lightweight solution to securely transmit data from an **AutoIt client** to a **PHP server** using Triple DES (3DES) encryption in CBC mode.

## 🚀 Quick Start & Usage Examples

### 1. Client-Side (AutoIt)
The client automatically appends an `"END"` control suffix to your text, encrypts it, and converts it into a clean Hexadecimal string ready for HTTP transmission.

**Example:**
```autoit
Global $SECRET_KEY = "MySecretKey"

; 1. Plaintext data to send
Local $sensitiveData = "User:Admin123"

; 2. Encrypt the data
Local $encryptedHex = _CryptSec($sensitiveData, True)
ConsoleWrite("Send this Hex string to your server: " & $encryptedHex & @CRLF)
; Expected Output: A long Hex string (e.g., 4E5A...)

; --- INTERNAL FUNCTION ---
Func _CryptSec($sText, $bEncrypt = True)
   Local $result = ""
   If $bEncrypt Then
      Local $plaintext = $sText & "END"
      Local $ciphertext = _Crypt_EncryptData($plaintext, $SECRET_KEY, $CALG_3DES)
      $result = Hex($ciphertext)
   Else
      Local $raw = Binary("0x" & $sText)
      Local $decryptedBinary = _Crypt_DecryptData($raw, $SECRET_KEY, $CALG_3DES)
      $result = StringTrimRight(BinaryToString($decryptedBinary), 3)
   EndIf
   Return $result
EndFunc
```

### 2. Server-Side (PHP)
The server receives the Hex string, validates it, decrypts it, and automatically verifies and strips the control suffix.

**Example:**
```php
$secretKey = "MySecretKey";

// Assume this is received from AutoIt via HTTP POST
$receivedHex = $_POST['data'] ?? '4E5A...'; 

$decryptedData = decrypt_data($receivedHex, $secretKey);

if ($decryptedData !== false) {
    echo "Success! Decrypted data: " . $decryptedData; 
    // Output: User:Admin123
} else {
    echo "Error: Data was corrupted or the secret key is invalid.";
}

// --- INTERNAL FUNCTION ---
function decrypt_data($hexText, $secretKey) {
    if (isset($hexText[1]) && $hexText[0] === '0' && ($hexText[1] === 'x' || $hexText[1] === 'X')) {
        $hexText = substr($hexText, 2);
    }
    $len = strlen($hexText);
    if ($len < 16 || ($len & 1) || !ctype_xdigit($hexText)) return false;
    $rawBinary = hex2bin($hexText);
    if ($rawBinary === false) return false;

    static $keyCache = [], $lastKey = null, $lastDerivedKey = null;
    if ($secretKey !== $lastKey) {
        if (!isset($keyCache[$secretKey])) {
            $baseHash = md5($secretKey, true);
            static $IPAD16, $OPAD16, $IPAD48, $OPAD48;
            if ($IPAD16 === null) {
                $IPAD16 = str_repeat("\x36", 16); $OPAD16 = str_repeat("\x5C", 16);
                $IPAD48 = str_repeat("\x36", 48); $OPAD48 = str_repeat("\x5C", 48);
            }
            $keyCache[$secretKey] = substr(md5(($baseHash ^ $IPAD16) . $IPAD48, true) . md5(($baseHash ^ $OPAD16) . $OPAD48, true), 0, 24);
        }
        $lastKey = $secretKey; $lastDerivedKey = $keyCache[$secretKey];
    }

    $decrypted = openssl_decrypt($rawBinary, 'des-ede3-cbc', $lastDerivedKey, OPENSSL_RAW_DATA, "\0\0\0\0\0\0\0\0");

    if ($decrypted === false || strlen($decrypted) < 3 || substr($decrypted, -3) !== 'END') {
        return false;
    }
    return substr($decrypted, 0, -3);
}
```

## 📌 Key Implementation Details
- Why the "END" suffix? Block ciphers like 3DES pad data with trailing null bytes (\0) to match block sizes. The "END" marker acts as a custom delimiter so the server knows exactly where the real data ends, while simultaneously serving as an integrity check to verify the correct password was used.
- **Best Practices**: Always transmit the encrypted Hex string via HTTP POST over an HTTPS connection. Avoid GET requests, as they leak encrypted payloads into server access logs and browser histories.
