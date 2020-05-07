package task40

import task39.RSA
import java.math.BigDecimal
import java.math.BigInteger
import java.math.MathContext
import kotlin.math.abs
import kotlin.math.log10
import kotlin.math.pow

fun cubeRoot(input: BigInteger): BigInteger = root(3, BigDecimal(input)).toBigInteger()

// n = основание, x = степень
private fun root(n: Int, x: BigDecimal): BigDecimal {

    var s = BigDecimal(x.toDouble().pow(1.0 / n))

    val nth = BigDecimal(n)

    val xhighpr = scalePrec(x, 2)
    val mc = MathContext(2 + x.precision())
    val eps: Double = x.ulp().toDouble() / (2 * n * x.toDouble())

    while (true) {
        var c = xhighpr.divide(s.pow(n - 1), mc)
        c = s.subtract(c)
        val locmc = MathContext(c.precision())
        c = c.divide(nth, locmc)
        s = s.subtract(c)
        if (abs(c.toDouble() / s.toDouble()) < eps) {
            break
        }
    }
    return s.round(MathContext(err2prec(eps)))
}

private fun scalePrec(x: BigDecimal, d: Int): BigDecimal {
    return x.setScale(d + x.scale())
}

private fun err2prec(xerr: Double): Int {
    return 1 + log10(abs(0.5 / xerr)).toInt()
}

//Используя теорему об остатках получаем дешифрованный текст
private fun rsaBroadcastAttack(textsEncrypted: List<Pair<BigInteger, BigInteger>>): BigInteger {
    val (c0, n0) = textsEncrypted[0]
    val (c1, n1) = textsEncrypted[1]
    val (c2, n2) = textsEncrypted[2]
    val m0 = n1 * n2
    val m1 = n0 * n2
    val m2 = n0 * n1

    val t0 = c0 * m0 * m0.modInverse(n0)
    val t1 = c1 * m1 * m1.modInverse(n1)
    val t2 = c2 * m2 * m2.modInverse(n2)

    val c = (t0 + t1 + t2) % (n0 * n1 * n2)
    return cubeRoot(c)
}

fun main() {
    val raw = "DNA"
    val rawBytes = raw.toByteArray()
    // Зашифровали фразу три раза, сохранили в textEncrypted вместе с открытыми ключами RSA

    val textsEncrypted = (1..3).map {
        val rsa = RSA(1024)
        rsa.encrypt(BigInteger(rawBytes)) to rsa.publicKey.second
    }

    println("Equals: ${rsaBroadcastAttack(textsEncrypted) == BigInteger(rawBytes)}")
    assert(rsaBroadcastAttack(textsEncrypted) == BigInteger(rawBytes))
}