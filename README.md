# AutoIt to PHP Secure Communication (3DES)

This project provides a lightweight, cross-platform encryption solution to securely transmit data from an **AutoIt client** to a **PHP server** using Triple DES (3DES) in CBC mode.

## Project Description

When communicating a desktop application (AutoIt) with a web server (PHP), passing sensitive data in plain text is a significant risk. This pair of functions solves that problem:
1. **Client-Side (AutoIt):** Encrypts a string using Windows' Native Cryptography API (`_Crypt_EncryptData`) with Triple DES (`$CALG_3DES`) and converts the binary output to a safe Hexadecimal string.
2. **Server-Side (PHP):** Validates the incoming hex string, derives the exact key using a custom MD5-based key derivation mechanism (fully optimized with static caching), and decrypts the data natively via OpenSSL (`des-ede3-cbc`).

---

## Why is the `"END"` Suffix Added?

If you look closely at the code, AutoIt appends `"END"` to the plaintext before encrypting, and PHP checks for it and strips it away at the end:

* **Handling Block Cipher Padding (The Main Reason):** Block ciphers like 3DES operate on blocks of fixed size (8 bytes). If the plaintext length is not a multiple of the block size, padding bytes are automatically added during encryption. When PHP decrypts the data using raw options, trailing null bytes (`\0`) or random padding characters can remain at the end of the string.
* **Integrity Check / End-of-String Marker:** The `"END"` suffix acts as a custom delimiter. By looking for `E-N-D` at the very end of the decrypted payload, the PHP server can instantly verify that the decryption process was successful and that the secret key used was correct. If `"END"` is missing, it safely rejects the payload without triggering fatal errors.

---

## GET vs POST Implementation Pros & Cons

Since you will be sending this encrypted Hex string over HTTP/S, choosing the right method matters.

| HTTP Method | Pros | Cons |
| :--- | :--- | :--- |
| **GET** (Query String) | * Easy to implement and test directly in a browser.<br>* Slightly faster overhead as it doesn't need a request body. | * **URL Length limits:** Hex strings grow significantly; long payloads will break the URL limit (approx. 2000 chars).<br>* **Security Risk:** Data gets saved in server access logs and browser/proxy history (even if encrypted, exposing metadata is bad practice). |
| **POST** (Request Body) | * **No Size Limits:** Perfect for sending large strings or structures.<br>* **Much Safer:** Data is hidden inside the body, meaning it won't be leaked into server access logs.<br>* **Cleanliness:** Keeps URLs clean and adheres to REST guidelines for data submission. | * Requires a tiny bit more boilerplate code in AutoIt to format the HTTP request headers. |

> **Recommendation:** Always use **POST** over an **HTTPS** connection. Encryption secures the data from being read, but HTTPS protects the entire transaction from man-in-the-middle tampering, and POST prevents sensitive tokens from ending up in system logs.

---

## Code Snippets

### Client (AutoIt)
```autoit
Func _CryptSec($sText, $bEncrypt = True)
   Local $result = ""
   If $bEncrypt Then
      Local $plaintext = $sText & "END"
      ; Encryption returns a binary type
      Local $ciphertext = _Crypt_EncryptData($plaintext, $SECRET_KEY, $CALG_3DES)
      ; Convert to Hex to make the result readable as text
      $result = Hex($ciphertext)
   Else
      ; Decryption
      ; Convert the input Hex back to binary
      Local $raw = Binary("0x" & $sText)
      Local $decryptedBinary = _Crypt_DecryptData($raw, $SECRET_KEY, $CALG_3DES)
      ; Convert binary to string and strip the "END" suffix
      $result = StringTrimRight(BinaryToString($decryptedBinary), 3)
   EndIf
   Return $result
EndFunc
```

### Server (PHP)
```php
function decrypt_data($hexText, $secretKey) {
    // 1. Prefix cleaning ('0x')
    if (isset($hexText[1]) && $hexText[0] === '0' && ($hexText[1] === 'x' || $hexText[1] === 'X')) {
        $hexText = substr($hexText, 2);
    }

    // 2. Early validation (Length, parity and valid hex characters)
    $len = strlen($hexText);
    if ($len < 16 || ($len & 1) || !ctype_xdigit($hexText)) {
        return false;
    }

    $rawBinary = hex2bin($hexText);
    if ($rawBinary === false) {
        return false;
    }

    // 3. Key derivation with static cache (Maximum performance)
    static $keyCache = [], $lastKey = null, $lastDerivedKey = null;
    
    if ($secretKey !== $lastKey) {
        if (!isset($keyCache[$secretKey])) {
            $baseHash = md5($secretKey, true);
            
            static $IPAD16, $OPAD16, $IPAD48, $OPAD48;
            if ($IPAD16 === null) {
                $IPAD16 = str_repeat("\x36", 16);
                $OPAD16 = str_repeat("\x5C", 16);
                $IPAD48 = str_repeat("\x36", 48);
                $OPAD48 = str_repeat("\x5C", 48);
            }
            
            $keyCache[$secretKey] = substr(
                md5(($baseHash ^ $IPAD16) . $IPAD48, true) .
                md5(($baseHash ^ $OPAD16) . $OPAD48, true),
                0,
                24
            );
        }
        $lastKey = $secretKey;
        $lastDerivedKey = $keyCache[$secretKey];
    }

    // 4. Decryption
    $decrypted = openssl_decrypt(
        $rawBinary,
        'des-ede3-cbc',
        $lastDerivedKey,
        OPENSSL_RAW_DATA,
        "\0\0\0\0\0\0\0\0" // Zero IV
    );

    // 5. Secure integrity check (Prevents Fatal Errors in PHP 8 if string is too short)
    if ($decrypted === false || strlen($decrypted) < 3 || $decrypted[-1] !== 'D' || $decrypted[-2] !== 'N' || $decrypted[-3] !== 'E') {
        return false;
    }

    return substr($decrypted, 0, -3);
}
```
