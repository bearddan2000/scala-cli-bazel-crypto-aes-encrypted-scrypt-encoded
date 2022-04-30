package example

import org.bouncycastle.crypto.generators.SCrypt;
import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

class Encode {

  val encryption = new Encryption()

  @throws(classOf[Exception])
  def encrypt(plainText: String): String = encryption.encryptPasswordBased(plainText);

  def hashpw(pass: String): String = {

    val SALT = "@amG89>";
    
    // DifficultyFactor
    // These should be powers of 2
    val cpu = 8;
    val memory = 8;
    val parallelism = 8;
    val outputLength = 32;

      val hash: Array[Byte] = SCrypt.generate(pass.getBytes(), SALT.getBytes(), cpu, memory, parallelism, outputLength);

      val stored: String = DatatypeConverter.printHexBinary(hash);

    try {

      return encrypt(stored);

    } catch {
      case e: Exception => {

      return "";
      }
    }

  }

  def verify(pass :String, hash: String): Boolean = {

    val newPass: String = hashpw(pass)

    return newPass.equals(hash)
  }
}
