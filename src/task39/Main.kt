package task39

import java.math.BigInteger
import java.util.*

class RSA(keyLength: Int) {
    private var phi = BigInteger.ZERO
    private var e = BigInteger("3")
    private var n = BigInteger.ZERO
    private var d = BigInteger.ZERO

    // Открытый ключ, 1 - экспонента, 2 - модуль
    val publicKey: Pair<BigInteger, BigInteger>

    init {
        val rnd = Random()
        while ((gcd(e, phi)) != BigInteger.ONE) {
            val p = BigInteger.probablePrime(keyLength / 2, rnd)
            val q = BigInteger.probablePrime(keyLength / 2, rnd)
            phi = lcm(p - BigInteger.ONE, q - BigInteger.ONE)
            n = p * q
        }
        d = e.modInverse(phi)
        publicKey = e to n
    }

    fun encrypt(raw: BigInteger): BigInteger {
        return raw.modPow(e, n)
    }

    fun decrypt(encrypted: BigInteger): BigInteger {
        return encrypted.modPow(d, n)
    }
}

//НОД
fun gcd(first: BigInteger, second: BigInteger): BigInteger {
    return first.gcd(second)
}

//НОК
fun lcm(first: BigInteger, second: BigInteger): BigInteger = first / gcd(first, second) * second

//Обратное по модулю число
fun invmod(a: BigInteger, n: BigInteger): BigInteger {
    var t = BigInteger.ZERO
    var r = n
    var tNew = BigInteger.ONE
    var rNew = a

    while (rNew != BigInteger.ZERO) {
        val quotient = r / rNew
        t = tNew
        tNew = t - (quotient * tNew)
        r = rNew
        rNew = r - (quotient * rNew)
    }

    if (r > BigInteger.ONE) {
        throw Exception("bad arg")
    }
    if (t < BigInteger.ZERO) {
        t += n
    }
    return t
}

@ExperimentalStdlibApi
fun main() {

    val rsa = RSA(keyLength = 512)
    val textForEncryption = "DNA DNA DNA DNA DNA DNA DNA DNA"
    val textForEncryptionBytes = textForEncryption.toByteArray()

    val encrypted = rsa.encrypt(BigInteger(textForEncryptionBytes))
    val decrypted = rsa.decrypt(encrypted)
    println("Original: $textForEncryption")
    println("Decrypted: ${decrypted.toByteArray().decodeToString()}")
    println("Encrypted bytes: $encrypted")
    println("Decrypted bytes: $decrypted")
    println("Equals: ${encrypted == BigInteger(textForEncryptionBytes)}")
    assert(rsa.decrypt(rsa.encrypt(BigInteger(textForEncryptionBytes))) == BigInteger(textForEncryptionBytes))
}