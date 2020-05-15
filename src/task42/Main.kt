package task42

import task39.RSA
import task40.cubeRoot
import java.math.BigInteger

val ASN_SHA1 = BigInteger(byteArrayOf(30, 21, 30, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 14))

class RSADigitalSignature(private val rsa: RSA) {

    fun verify(encryptedSignature: BigInteger, message: String): Boolean {
        val signature = BigInteger("00", 16) + rsa.encrypt(encryptedSignature)
        val r = Regex("0001ff+?00.{15}.{20}]", RegexOption.DOT_MATCHES_ALL)

        if (!r.matches(signature.toString(16))) {
            return false
        }
        val m = r.matchEntire(signature.toString(16))
        val first = BigInteger(m!!.groupValues.first(), 16)
        return first == message.toByteArray().toBigInteger()
    }
}

fun forgeSignature(message: String, keyLength: Int): BigInteger {
    val block = BigInteger(byteArrayOf(0, 1, (255).toByte(), 0)) + ASN_SHA1 + message.toByteArray().toBigInteger()
    val garbage = BigInteger("00".repeat(((keyLength + 7) / 8) - block.bitLength()), 16)
    block.add(garbage)

    return cubeRoot(block)
}

fun ByteArray.toBigInteger() = BigInteger(this)

fun main() {
    val message = "all girls are the same"
    val forgedSignature = forgeSignature(message, 1024)

    println("${RSADigitalSignature(RSA(1024)).verify(forgedSignature, message)}")

}