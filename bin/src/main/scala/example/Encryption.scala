package example;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

class Encryption {

  val password = "@amG89>";
  val salt = generateSalt(256);
  val ivParameterSpec = generateIv();

  val key = getKeyFromPassword(password,salt);

    @throws ( classOf[Exception]  )
    def encrypt(algorithm :String, input :String, key :SecretKey, iv :IvParameterSpec) : String =
    {
        val cipher :Cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        val cipherText :Array[Byte] = cipher.doFinal(input.getBytes())
        return Base64.getEncoder().encodeToString(cipherText)
    }

    @throws (classOf[Exception])
    def generateKey(n :Int) :SecretKey = {
        val keyGenerator :KeyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(n)
        return keyGenerator.generateKey()
    }

    @throws (classOf[Exception])
    def generateSalt(n: Int): String = {
       val key = generateKey(n);
       return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @throws (classOf[Exception] )
    def getKeyFromPassword(password :String, salt :String) : SecretKey =
    {
        val factory :SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec :KeySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256)
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES")
    }

    def generateIv() :IvParameterSpec = {
        val iv = new Array[Byte](16)
        new SecureRandom().nextBytes(iv)
        return new IvParameterSpec(iv)
    }

    @throws ( classOf[Exception] )
    def encryptPasswordBased(plainText :String) : String =
    {
        val cipher :Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()))
    }
    @throws ( classOf[Exception] )
    def decryptPasswordBased(cipherText: String): String = {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return new String(cipher.doFinal(Base64.getDecoder()
            .decode(cipherText)));
    }

}
