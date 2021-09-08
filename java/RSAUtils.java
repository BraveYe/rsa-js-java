package com.common.security.util;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {
    public static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    public static final int KEY_SIZE_2048 = 2048;
    public static final int KEY_SIZE_1024 = 1024;

    private RSAUtils() {
    }

    private static final String ALGORITHM = "RSA";

    public static KeyPair generateKeyPair() {
        return generateKeyPair(KEY_SIZE_2048);
    }

    public static KeyPair generateKeyPair(int keySize) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Failed to generate key pair!", e);
        }
    }

    public static PublicKey getPublicKey(String base64PublicKey) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(base64PublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get public key!", e);
        }
    }

    public static PublicKey getPublicKey(BigInteger modulus, BigInteger exponent) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get public key!", e);
        }
    }

    public static String getBase64PublicKey(PublicKey publicKey) {
        return Base64.encodeBase64String(publicKey.getEncoded());
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(base64PrivateKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get private key!", e);
        }
    }

    public static PrivateKey getPrivateKey(BigInteger modulus, BigInteger exponent) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, exponent);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get private key!", e);
        }
    }

    public static String getBase64PrivateKey(PrivateKey privateKey) {
        return Base64.encodeBase64String(privateKey.getEncoded());
    }

    public static byte[] encryptAsByteArray(String data, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            throw new IllegalArgumentException("Encrypt failed!", e);
        }
    }

    public static byte[] encryptAsByteArray(String data, String base64PublicKey) {
        return encryptAsByteArray(data, getPublicKey(base64PublicKey));
    }

    public static String encryptAsString(String data, PublicKey publicKey) {
        return Base64.encodeBase64String(encryptAsByteArray(data, publicKey));
    }

    public static String encryptAsString(String data, String base64PublicKey) {
        return Base64.encodeBase64String(encryptAsByteArray(data, getPublicKey(base64PublicKey)));
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(data));
        } catch (Exception e) {
            throw new IllegalArgumentException("Decrypt failed!", e);
        }
    }

    public static String decrypt(byte[] data, String base64PrivateKey) {
        return decrypt(data, getPrivateKey(base64PrivateKey));
    }

    public static String decrypt(String data, PrivateKey privateKey) {
        return decrypt(Base64.decodeBase64(data), privateKey);
    }

    public static String decrypt(String data, String base64PrivateKey) {
        return decrypt(Base64.decodeBase64(data), getPrivateKey(base64PrivateKey));
    }
    
    
    public static void main(String[] args) {
//    	KeyPair keyPair = RSAUtils.generateKeyPair();
//    	PublicKey publicKey = keyPair.getPublic();
//    	System.out.println("publicKey:"+Base64.encodeBase64String(publicKey.getEncoded()));
//    	String rsaEncryptStr = RSAUtils.encryptAsString("12345678", publicKey);
//    	System.out.println("rsaEncryptStr:"+rsaEncryptStr);
//    	PrivateKey privateKey = keyPair.getPrivate();
//    	System.out.println("privateKey:"+Base64.encodeBase64String(privateKey.getEncoded()));
//    	String rsaDecryptStr = RSAUtils.decrypt(rsaEncryptStr, privateKey);
//    	System.out.println("rsaDecryptStr:"+rsaDecryptStr);
    	String rsaDecryptStr = RSAUtils.decrypt("VokmHOgx3f3xhrpNlu61dlmGUrs9siVofvTKmVBe6l/y65PypZwYIOPCDmT0gxwWsjAKupyo/7Gf3zvGFRpDRbfpzPBTtxXekjYazI5VO50ksiOQ6bfY+Qq9v3tRcLF/d6X3cfASJaGXQY/iKUsvxuFyAvtZaoilliB9KHFhCcY1YMN+mW5PZ/FmSF2SDDaRHncKGkRNvzANa1uAmNGHfXjQeH9bAi6/OLF6RkRDe1UADi2Z1Qfp+3JxPH47iuv79r5jHc3fEygY/ve1ZyO7k/ZSaJRsZbkm+pNFeZ7yNFl8ALNEDXbZDA6L+o68wi39OwY6hXs6wiWgI7pWUeeK3g==", "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVQjAyeE3YjBS3Jgt9s8KWWHMqCKuvv5o06CrHLp+qWraWX7Bo9pWZ1QXbu3b7iiyeZ04eQw+7TJYkcqqwF400xN0OkIVWnYdRYSIUqJ9lGmwAy/BAYMNmPiYoaVUXunl4tVc746edo/BrD3XUfAVuekhCK+pkvDOFu/LcNRmHgZzb8fFvuZuq5li3H/hle8881L3BDrXc9KVhQwcFuowLt3WBAUvVz8VG5RX+dW+L2rhu2G54j28VQpEqmEGOUyjtLKQMDNr5BCmCm55mUAEk0NwutaW72euQEURv4PRe0D1WIaXmnc0/OV8gxYoLqPe8WeYM7eqYP1ixV2gWBjcZAgMBAAECggEAdjNgb9eN7nugvBnI59c/tkh9i0Aqlpepy1RA7FQj5YjJJ/THg5gjiRuF9ClVZIZcJ2WwG48IGk/gZyTXv3QnQy7T0QDqV1mRHAVMNAgFks+F0Guw64q1s3ZsSXyBArWOFOWnG6qBxvlZH6+ypH9C3ebA6oZUrUnNk47wGSuD+CabDVo9h8CouZMAnEQyMAKKbosTGHCRh8VR5M5ii1WjUfWBt4ELnkdT89B4UmI5DkP+aW/yN5pJteeTIIrIcABEgid0dnw7/E4ZWrLlMm72wY+E0D07H2/O48IC5aFo1eioXweELmqaUfG5NEBBBaraxdqhy+zktx1Wkp7pJI/4wQKBgQDJoNfM7GwStqBq/Pvj3tw6WpQlJvSV2se6LSj6fmDpUgq/rJmmocqY2B+J6w9ZRzfeJOHaNXtu6qjwr7q4PGjPwQO3ymb7xx2j2VxitWRijHK18Goyhs2Pbixn5NF3rQbR1pML96wzP69sEXkMg8kkFWiUxauxa6cvNpB92xNg7QKBgQC9ghDBrJtyh5SfL0F3VX3PophZIdP+dyReCvZ6fyQ2d6c1BpC1U37ClYoedcz7pkuzacvTTWoOufQp9bJNduLtX8tKONhFPLPOo66NP9h0oFjovs638bHJXHf6FMawpciPbbiwmAm6X3KIqh1oXtYExuYSrm9Dq6/ARzHfsmjlXQKBgDxNt91ZZKVgK7B0A55OnE1zo9VMxmA/c/bx5MyumauO1xomtDnLL/3wvdYREKEiFMqC+225CzbMRkTeOhk6MBra3pLMnWp2Th4gN2pqWCDFYtWZlxmPidF5IRzdqeyCOoTuCULOC5m0VXIb87lTfQgmwwWj7Ur+KJ2NUz/hEvWtAoGAVrAXsDCgDxz8HHFGdisyWPfczvENg5rGlQpYw6JDU3MalsQBECE4nBRB0Ts74GWqvVCI/4irGj9v9H3C6XKXzdQDL1mffNSOv9jaMRzijD8JTLZz42r5U84rx8cXOJktjIa5dHaoBIxC3UdMGoE/T4IYnrUSipcP11n584UuPLUCgYABP1V/oSEGW5RK6UJGPxpNY2X1V7v/Uw2Fv1CsuMvQAy06h532UNx53N8XUjW5dQA8v2cUy3w5ue9K/H1lZpO7UnViQnMlcEGIXHfv0oqdDOCYq7hzodULgVE0YC0ycR3HsRXlLwAgb9uQSzl9bBAxrTrL7w5k41TJ1/nZ6MNcwQ==");
    	System.out.println("rsaDecryptStr:"+rsaDecryptStr);
    	
	}
}
