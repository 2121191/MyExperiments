package com.myrsa.demo.rsa;

import java.io.Serializable;
import java.math.BigInteger;
/**
 * 封装 RSA 公钥和私钥的类。
 * 便于保存和加载密钥对。
 */
public class RSAKeyPair implements Serializable {
    private static final long serialVersionUID = 1L; //用于序列化

    private BigInteger publicKeyExponent; //公钥指数e
    private BigInteger privateKeyExponent; //私钥指数d
    private BigInteger modulus; //模数n

    public RSAKeyPair(BigInteger publicKeyExponent, BigInteger privateKeyExponent, BigInteger modulus) {
        this.publicKeyExponent = publicKeyExponent;
        this.privateKeyExponent = privateKeyExponent;
        this.modulus = modulus;
    }

    public BigInteger getPublicKeyExponent() {
        return publicKeyExponent;
    }

    public BigInteger getPrivateKeyExponent() {
        return privateKeyExponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    //toString 方法方便调试和显示
    @Override
    public String toString() {
        return "RSAKeyPair{" +
               "\n  e=" + publicKeyExponent.toString(10) +
               "\n  d=" + privateKeyExponent.toString(10) +
               "\n  n=" + modulus.toString(10) +
               "\n}";
    }

    //获取公钥字符串
    public String getPublicKeyString() {
        return "e: " + publicKeyExponent.toString(10) + "\nn: " + modulus.toString(10);
    }

    //获取私钥字符串
    public String getPrivateKeyString() {
        return "d: " + privateKeyExponent.toString(10) + "\nn: " + modulus.toString(10);
    }
}