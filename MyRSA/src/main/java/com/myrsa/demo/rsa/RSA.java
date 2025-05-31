package com.myrsa.demo.rsa;

import java.math.BigInteger;
import java.security.MessageDigest; //引入SHA
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class RSA {
    // private static final BigInteger PUBLIC_EXPONENT = new BigInteger("65537"); //e想要写成静态
    private static final int SHA256_HASH_BYTE_LENGTH = 32; // SHA-256 哈希值的固定字节长度

    /**
     * 生成 RSA 密钥对
     * @param keySizeBits 密钥位数 (512, 1024, 2048)
     * @return RSAKeyPair 对象
     * @throws IllegalArgumentException
     */
    public static RSAKeyPair generateKeyPair(int keySizeBits) {
        if (keySizeBits < 512) {
            throw new IllegalArgumentException("Key size must be at least 512 bits for security reasons.");
        }

        SecureRandom random = new SecureRandom();
        BigInteger p, q, n, phi, e, d; // 我们要用到的数据

        // 随机生成大素数q和p
        do {
            p = BigInteger.probablePrime(keySizeBits / 2, random);
            q = BigInteger.probablePrime(keySizeBits / 2, random);
        } while (p.equals(q) || p.subtract(q).abs().bitLength() < (keySizeBits / 2) - 100); //确保p和q不相等且有足够大的差值

        // n = p * q
        n = p.multiply(q);

        // 计算欧拉 phi(n) = (p-1)(q-1)
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // 生成公钥e
        // 1 < e < phi(n) 且 gcd(e, phi(n)) = 1
        do {
            e = new BigInteger(16, random); // 随机生成一个 16位长的e
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !phi.gcd(e).equals(BigInteger.ONE));

        // 私钥d,e的逆元
        d = e.modInverse(phi);

        return new RSAKeyPair(e, d, n);
    }

    /**
     * 对消息进行 SHA-256 哈希处理。
     * @return 消息的 SHA-256 哈希值 (BigInteger 形式)
     * @throws NoSuchAlgorithmException 如果 SHA-256 算法不可用
     */
    public static BigInteger hashMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes());
        // 确保 BigInteger 始终是正数且无符号
        return new BigInteger(1, hashBytes);
    }

    /**
     * 哈希你嘿嘿
     * @return Base64 编码的 SHA-256 哈希字符串
     * @throws NoSuchAlgorithmException 如果 SHA-256 算法不可用
     */
    public static String hashMessageToBase64(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    /**
     * RSA 加密
     * @return Base64 编码的密文
     * @throws IllegalArgumentException 如果明文长度超过密钥模数n的长度
     */
    public static String encrypt(String plaintext, BigInteger publicKeyExponent, BigInteger modulus) {
        byte[] plaintextBytes = plaintext.getBytes();
        BigInteger m = new BigInteger(1, plaintextBytes);

        if (m.compareTo(modulus) >= 0) {
            throw new IllegalArgumentException("Plaintext is too large for the given key size. Please use a shorter message or a larger key.");
        }
        // C = M^e mod n
        BigInteger c = m.modPow(publicKeyExponent, modulus);
        return Base64.getEncoder().encodeToString(c.toByteArray());
    }

    /**
     * RSA 解密
     * @return 解密后的明文
     * @throws IllegalArgumentException 如果密文格式不正确
     */
    public static String decrypt(String ciphertextBase64, BigInteger privateKeyExponent, BigInteger modulus) {
        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertextBase64);
        BigInteger c = new BigInteger(1, ciphertextBytes);

        //M = C^d mod n
        BigInteger m = c.modPow(privateKeyExponent, modulus);
        byte[] decryptedBytes = m.toByteArray();//明文转成字节

        if (decryptedBytes.length > 1 && decryptedBytes[0] == 0x00) {
            byte[] tmp = new byte[decryptedBytes.length - 1];
            System.arraycopy(decryptedBytes, 1, tmp, 0, tmp.length);
            return new String(tmp);
        }
        return new String(decryptedBytes);
    }

    /**
     * 签名
     * @return Base64 编码的签名数据
     * @throws NoSuchAlgorithmException 如果 SHA-256 算法不可用
     */
    public static String sign(String message, BigInteger privateKeyExponent, BigInteger modulus)
            throws NoSuchAlgorithmException {
        BigInteger hash = hashMessage(message);

        // 签名S = (Hm)^d mod n
        BigInteger s = hash.modPow(privateKeyExponent, modulus);

        return Base64.getEncoder().encodeToString(s.toByteArray());
    }

    /**
     * 验签
     * @return true 签名有效，false 签名无效
     * @throws NoSuchAlgorithmException SHA-256 算法不可用
     */
    public static boolean verify(String message, String signatureBase64, BigInteger publicKeyExponent, BigInteger modulus)
            throws NoSuchAlgorithmException {
        BigInteger originalHash = hashMessage(message); // Uses new BigInteger(1, byte[])

        // 解码 Base64 签名到 BigInteger
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        // 确保 BigInteger 始终是正数且无符号
        BigInteger s = new BigInteger(1, signatureBytes);

        // 计算 H' = S^e mod n
        BigInteger decryptedHash = s.modPow(publicKeyExponent, modulus);

        return originalHash.equals(decryptedHash);
    }

    /**
     * @param bigInt 要转换的 BigInteger
     * @param targetLength 目标字节数组长度
     * @return 固定长度的字节数组
     */
    public static byte[] bigIntToFixedLengthBytes(BigInteger bigInt, int targetLength) {
        byte[] bytes = bigInt.toByteArray();
        if (bytes.length == targetLength) {
            return bytes;
        } else if (bytes.length > targetLength) {

            if (bytes[0] == 0x00 && bytes.length == targetLength + 1) { // 典型的 BigInteger.toByteArray() 添加0x00的情况
                return Arrays.copyOfRange(bytes, 1, targetLength + 1);
            } else {

                return Arrays.copyOfRange(bytes, bytes.length - targetLength, bytes.length);
            }
        } else { // bytes.length < targetLength
            byte[] paddedBytes = new byte[targetLength];
            System.arraycopy(bytes, 0, paddedBytes, targetLength - bytes.length, bytes.length);
            return paddedBytes;
        }
    }
}