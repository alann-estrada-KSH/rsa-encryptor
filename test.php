<?php

// En este archivo se van a encriptar las cadenas que se les pase

function rsaEncryptWithPython($viHex, $saltHex, $passphrase, $certFilePath)
{
    $pData = "$viHex::$saltHex::$passphrase";

    $payload = json_encode([
        'message' => $pData,
        'cert_path' => $certFilePath
    ]);

    $ch = curl_init('http://localhost:5000/encrypt');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200) {
        throw new Exception('Error HTTP al comunicarse con Python: ' . $httpCode);
    }

    $json = json_decode($response, true);
    if (!isset($json['encrypted_base64'])) {
        throw new Exception('Error al cifrar con el servicio Python: ' . $response);
    }

    return $json['encrypted_base64'];
}
