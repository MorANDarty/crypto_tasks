package task41

import task39.RSA
import java.math.BigInteger
import java.util.*

class RSAServer(private val rsa: RSA) {
    private var decrypteds: MutableSet<BigInteger> = mutableSetOf()

    fun getPublicKey() = rsa.publicKey

    fun decrypt(encrypted: BigInteger): BigInteger {
        if (encrypted in decrypteds) {
            return rsa.decrypt(encrypted)
        }
        decrypteds.add(encrypted)
        return rsa.decrypt(encrypted)
    }
}

fun messageRecovery(ecrypted: BigInteger, rsaServer: RSAServer): BigInteger {
    val (e, n) = rsaServer.getPublicKey()

    var s: BigInteger
    while (true) {
        s = nextRandomBigInteger(n - BigInteger.ONE)
        if (s % n > BigInteger.ONE) break
    }

    // зашифровываем подделку
    val newEncrypted = (s.modPow(e, n) * ecrypted) % n
    // расшифровываем её
    val newDecrypted = rsaServer.decrypt(newEncrypted)
    return newDecrypted * s.modInverse(n) % n
}


private fun nextRandomBigInteger(n: BigInteger): BigInteger {
    val rnd = Random()
    var result = BigInteger(n.bitLength(), rnd)
    while (result >= n) {
        result = BigInteger(n.bitLength(), rnd)
    }
    return result
}


@ExperimentalStdlibApi
fun main() {
    val raw = "Good job"
    val rawByteArray = raw.toByteArray()
    val rsa = RSA(1024)
    val encrypted = rsa.encrypt(BigInteger(rawByteArray))
    val rsaServer = RSAServer(rsa)

    val recoveredByteArray = messageRecovery(encrypted, rsaServer).toByteArray()!!
    val recovered = recoveredByteArray.decodeToString()
    println("Original: $raw")
    println("Recovered: $recovered")
    println(recovered == raw)
    assert(recovered == raw)

}