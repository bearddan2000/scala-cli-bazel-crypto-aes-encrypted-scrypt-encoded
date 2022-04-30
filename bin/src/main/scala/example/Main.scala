/*
 * copyright
 * http://timarcher.com/blog/2007/04/simple-java-class-to-des-encrypt-strings-such-as-passwords-and-credit-card-numbers/
 */

package example;

object Main {

  def printVerify(pass1: String, pass2: String, test: Boolean): Unit =
  {
    val baseStr: String = "%s, %s".format(pass1, pass2)

    if(test) {
      println("%s Match: True".format(baseStr))
    } else {
      println("%s Match: False".format(baseStr))
    }
  }

  // Driver code
  @throws(classOf[Exception])
  def main(args: Array[String]): Unit =
  {
      val encode = new Encode()

      val hash: String = encode.hashpw("pass123");

      val test1: Boolean = encode.verify("pass123", hash);

      val test2: Boolean = encode.verify("123pass", hash);
      
      printVerify("pass123", "pass123", test1)

      printVerify("pass123", "123pass", test2)
  }

}
