package de.fluttercrypto.aes_playground_native;

import android.os.Build.VERSION_CODES;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

// crypto start
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
// crypto end

import java.util.Map;

import io.flutter.embedding.android.FlutterActivity;
import io.flutter.embedding.engine.FlutterEngine;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.MethodCall;

public class MainActivity extends FlutterActivity {

    private static final String CRYPTO_CHANNEL = "de.fluttercrypto/crypto";

    @Override
    public void configureFlutterEngine(@NonNull FlutterEngine flutterEngine) {
        new MethodChannel(flutterEngine.getDartExecutor(), CRYPTO_CHANNEL).setMethodCallHandler(
                new MethodCallHandler() {
                    @RequiresApi(api = VERSION_CODES.KITKAT)
                    @Override
                    public void onMethodCall(MethodCall call, Result result) {
                        String callMethod = call.method;
                        Map<String, String> arguments = call.arguments();
                        switch (callMethod) {
                            case "aesCbcEnc":
                                String passwordCbcEnc = arguments.get("password");
                                String iterationsCbcEnc = arguments.get("iterations");
                                String plaintextCbcEnc = arguments.get("plaintext");
                                String resultStringCbcEnc = "";
                                char[] passwordCharCbcEnc = passwordCbcEnc.toCharArray();
                                resultStringCbcEnc = aesCbcPbkdf2EncryptToBase64Android(passwordCharCbcEnc, iterationsCbcEnc, plaintextCbcEnc);
                                result.success(resultStringCbcEnc);
                                break;
                            case "aesCbcDec":
                                String passwordCbcDec = arguments.get("password");
                                String ciphertextCbcDec = arguments.get("ciphertext");
                                String resultStringCbcDec = "";
                                char[] passwordCharCbcDec = passwordCbcDec.toCharArray();
                                resultStringCbcDec = aesCbcPbkdf2DecryptFromBase64Android(passwordCharCbcDec, ciphertextCbcDec);
                                result.success(resultStringCbcDec);
                                break;

                            case "aesGcmEnc":
                                String passwordGcmEnc = arguments.get("password");
                                String iterationsGcmEnc = arguments.get("iterations");
                                String plaintextGcmEnc = arguments.get("plaintext");
                                String resultStringGcmEnc = "";
                                char[] passwordCharGcmEnc = passwordGcmEnc.toCharArray();
                                resultStringGcmEnc = aesGcmPbkdf2EncryptToBase64Android(passwordCharGcmEnc, iterationsGcmEnc, plaintextGcmEnc);
                                result.success(resultStringGcmEnc);
                                break;
                            case "aesGcmDec":
                                String passwordGcmDec = arguments.get("password");
                                String ciphertextGcmDec = arguments.get("ciphertext");
                                String resultStringGcmDec = "";
                                char[] passwordCharGcmDec = passwordGcmDec.toCharArray();
                                resultStringGcmDec = aesGcmPbkdf2DecryptFromBase64Android(passwordCharGcmDec, ciphertextGcmDec);
                                result.success(resultStringGcmDec);
                                break;

                            default:
                                result.notImplemented();
                                break;
                        }

                    }
                }
        );
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesCbcPbkdf2EncryptToBase64Android(char[] passphrase, String iterationsString, String data) {
        int PBKDF2_ITERATIONS = 0;
        try {
            PBKDF2_ITERATIONS = Integer.parseInt(iterationsString);
        } catch(NumberFormatException nfe) {
            PBKDF2_ITERATIONS = 10000; // minimum
        }
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        byte[] salt = generateSalt32Byte();
        byte[] iv = generateRandomIv();
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] ciphertextWithTag = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String saltBase64 = base64Encoding(salt);
            //String roundsString = String.valueOf(PBKDF2_ITERATIONS);
            String ivBase64 = base64Encoding(iv);
            String ciphertextBase64 = base64Encoding(ciphertextWithTag);
            return
                    saltBase64 + ":" + ivBase64 + ":" + ciphertextBase64;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesCbcPbkdf2DecryptFromBase64Android(char[] passphrase, String data) {
        String[] parts = data.split(":", 0);
        byte[] salt = base64Decoding(parts[0]);
        String iterationsString = parts[1];
        byte[] iv = base64Decoding(parts[2]);
        byte[] ciphertextWithTag = base64Decoding(parts[3]);
        int PBKDF2_ITERATIONS = 0;
        try {
            PBKDF2_ITERATIONS = Integer.parseInt(iterationsString);
        } catch(NumberFormatException nfe) {
            PBKDF2_ITERATIONS = 10000; // minimum
        }
        if ((salt.length != 32) | (iv.length != 16) | (ciphertextWithTag.length < 16)) return "";
        // key derivation
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedtext = cipher.doFinal(ciphertextWithTag);
            return new String(decryptedtext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }


    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2EncryptToBase64Android(char[] passphrase, String iterationsString, String data) {
        int PBKDF2_ITERATIONS = 0;
        try {
            PBKDF2_ITERATIONS = Integer.parseInt(iterationsString);
        } catch(NumberFormatException nfe) {
            PBKDF2_ITERATIONS = 10000; // minimum
        }
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        byte[] salt = generateSalt32Byte();
        byte[] nonce = generateRandomNonce();
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NOPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] ciphertextWithTag = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String saltBase64 = base64Encoding(salt);
            //String roundsString = String.valueOf(PBKDF2_ITERATIONS);
            String nonceBase64 = base64Encoding(nonce);
            String ciphertextBase64 = base64Encoding(ciphertextWithTag);
            return
                    saltBase64 + ":" + nonceBase64 + ":" + ciphertextBase64;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2DecryptFromBase64Android(char[] passphrase, String data) {
        String[] parts = data.split(":", 0);
        byte[] salt = base64Decoding(parts[0]);
        String iterationsString = parts[1];
        byte[] nonce = base64Decoding(parts[2]);
        byte[] ciphertextWithTag = base64Decoding(parts[3]);
        int PBKDF2_ITERATIONS = 0;
        try {
            PBKDF2_ITERATIONS = Integer.parseInt(iterationsString);
        } catch(NumberFormatException nfe) {
            PBKDF2_ITERATIONS = 10000; // minimum
        }
        if ((salt.length != 32) | (nonce.length != 12) | (ciphertextWithTag.length < 16)) return "";
        // key derivation
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NOPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] decryptedtext = cipher.doFinal(ciphertextWithTag);
            return new String(decryptedtext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    private static byte[] generateSalt32Byte() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static byte[] generateRandomIv() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
        return nonce;
    }
    
    private static byte[] generateRandomNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }
}