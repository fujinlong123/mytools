package com.fujinlong.secret;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Base64;


/*<script type="text/javascript">
function init(){

    var keyHex = CryptoJS.enc.Base64.parse('rUqSznmiv78=');
    ///var keyHex = CryptoJS.enc.Utf8.parse('rUqSznmiv78=');

    var encrypted = CryptoJS.DES.encrypt('87654321', keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    alert(encrypted.toString());
    ///alert(encrypted.ciphertext.toString(CryptoJS.enc.Base64));

    // direct decrypt ciphertext
    var decrypted = CryptoJS.DES.decrypt({
            ciphertext: CryptoJS.enc.Base64.parse(encrypted.toString())
        }, keyHex, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
     });
    alert(decrypted.toString(CryptoJS.enc.Utf8));
}
</script>*/


/**
 * DES对称加密算法
 * @see 
 */
public class DESCoder {
//  public static final String KEY_ALGORITHM = "DESede";
//  public static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";

    public static final String KEY_ALGORITHM = "DES";
    public static final String CIPHER_ALGORITHM = "DES/ECB/PKCS7Padding";

//  /**
//   * 生成密钥
//   * @see Java6只支持56位密钥
//   * @see BouncyCastle支持64位密钥，官网是http://www.bouncycastle.org/
//   */
//  public static String initkey() throws NoSuchAlgorithmException {
//      KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
//      kg.init(168);
//      SecretKey secretKey = kg.generateKey();
//      
//      return Base64.encodeBase64String(secretKey.getEncoded());
//  }

    /**
     * 生成密钥
     * @param seed 密钥
     * @return 字符串
     * @throws Exception 异常
     */
    public static String initkey() throws Exception {
        return initkey(null);
    }

    /**
     * 生成密钥
     * @param seed 密钥
     * @return 字符串
     * @throws Exception 异常
     */
    public static String initkey(String seed) throws Exception {
        SecureRandom secureRandom = null;

        if(seed != null){
            secureRandom = new SecureRandom(Base64.decodeBase64(seed));
        }else{
            secureRandom = new SecureRandom();
        }

        KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        kg.init(secureRandom);
        SecretKey secretKey = kg.generateKey();

        return Base64.encodeBase64String(secretKey.getEncoded());
    }

//  /**
//   * 转换密钥
//   */
//  private static Key toKey(byte[] key) throws Exception {
//      DESedeKeySpec dks = new DESedeKeySpec(key);
//      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
//      SecretKey secretKey = keyFactory.generateSecret(dks);
//      return secretKey;

//  }
    /**
     * 转换密钥
     */
    private static SecretKey toKey(byte[] key) throws Exception {
        DESKeySpec keySpec = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        return secretKey;
    }

    /**
     * 加密数据
     * @param data 待加密数据
     * @param key  密钥
     * @return 加密后的数据
     */
    public static String encrypt(String data, String key) throws Exception {
        Key k = toKey(Base64.decodeBase64(key));
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, k);
        byte[] encryptData = cipher.doFinal(data.getBytes());
        return Base64.encodeBase64String(encryptData);
    }

    /**
     * 解密数据
     * @param data 待解密数据
     * @param key  密钥
     * @return 解密后的数据
     */
    public static String decrypt(String data, String key) throws Exception {
        Key k = toKey(Base64.decodeBase64(key));
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, k);
        return new String(cipher.doFinal(Base64.decodeBase64(data)));
    }

    public static void main(String[] args) throws Exception {
        String source ="{\"MchannelId\":\"PMBS\",\"IdType\":\"0\",\"IdNo\":\"430321199001236250\"}";
        System.out.println("原文: " + source);
       // rUqSznmiv78=
        String key = "ZkprfV3R";
        System.out.println("密钥: " + key);

        String encryptData =encrypt(source, key);
        System.out.println("加密: " + encryptData);

        String decryptData = decrypt(encryptData, key);
        System.out.println("解密: " + decryptData);
    }
}