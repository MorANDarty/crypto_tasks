package task46

import task39.RSA
import task42.toBigInteger
import java.math.BigDecimal
import java.math.BigInteger
import java.util.*

class RSAParityOracle(val rsa: RSA) {

    fun isParityOdd(encryptedData: BigInteger): Boolean {
        return encryptedData.modPow(rsa.publicKey.first, rsa.publicKey.second).mod(BigInteger.TWO) == BigInteger.ZERO
    }


    fun decrypt(bigInteger: BigInteger) = rsa.decrypt(bigInteger)

    fun encrypt(bigInteger: BigInteger) = rsa.encrypt(bigInteger)

}

fun parityOracleAttack(cipherTest: BigInteger, rsaParityOracle: RSAParityOracle): BigInteger {
    val (e, n) = rsaParityOracle.rsa.publicKey
    val multiplayer = BigInteger.TWO.modPow(e, n)

    var lowerBound = BigDecimal(0)
    var upperBound = BigDecimal(n)

    while (lowerBound < upperBound.minus(BigDecimal.ONE)) {
        var s = (cipherTest * multiplayer) % n
        val mid = (lowerBound + upperBound).div(BigDecimal(2))
        if (rsaParityOracle.isParityOdd(cipherTest)) {
            lowerBound = mid
        } else {
            upperBound = mid
        }
    }
    return upperBound.toBigInteger()
}


fun main() {

    val inputBytes = Base64.getDecoder().decode(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    )
    val rsaParityOracle = RSAParityOracle(RSA(1024))
    val cipherText = rsaParityOracle.encrypt(inputBytes.toBigInteger())

    val decr = rsaParityOracle.decrypt(cipherText)

    val plainText = parityOracleAttack(cipherText, rsaParityOracle)

    println("$plainText == ${inputBytes.toBigInteger()}")
    println("${plainText == inputBytes.toBigInteger()}")


}