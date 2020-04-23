package task33

import java.math.BigInteger
import java.util.*

class DiffieHellman(
    private val p: BigInteger,
    private val g: BigInteger
) {
    private val privateKey: BigInteger = BigInteger(1023, Random())
    fun publicKey() = modPow(g, privateKey, p)
    fun sharedKey(pubKey: BigInteger) = modPow(pubKey, privateKey, p)

    private fun modPow(
        power: BigInteger,
        num: BigInteger,
        divider: BigInteger
    ): BigInteger {
        var x = num
        var a = power
        var result = BigInteger("1")

        while (x > BigInteger.ZERO) {
            if (x.mod(BigInteger("2")) == BigInteger.ONE) {
                result = result.multiply(a).mod(divider)
            }
            x = x.shiftRight(1)
            a = a.multiply(a).mod(divider)
        }
        return result
    }
}