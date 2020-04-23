package task35

import DEFAULT_G
import DEFAULT_P
import aesCbcDecrypt
import aesCbcEncrypt
import hash
import iv
import randomByteArray
import task33.DiffieHellman
import toHex
import java.math.BigInteger

class Main {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val p = DEFAULT_P
            val maliciousG = listOf<BigInteger>(BigInteger.ONE, p, p.minus(BigInteger.ONE))

            maliciousG.forEach { g ->
                val aliceDh = DiffieHellman(p, DEFAULT_G)
                val bob = DiffieHellman(p, g)

                val B = bob.publicKey()

                val message = "Simple message".toByteArray()
                val aKey = aliceDh.sharedKey(B).hash()
                val aIV = randomByteArray()

                val msgFromAliceEncrypted = aesCbcEncrypt(aKey, aIV, message) + aIV

                val mitmAIV = msgFromAliceEncrypted.iv()

                var mitmHackedKey: ByteArray
                var mitmHackedMessage: ByteArray? = null
                when (g) {
                    BigInteger.ONE -> {
                        mitmHackedKey = BigInteger.ONE.hash()
                        mitmHackedMessage = aesCbcDecrypt(mitmAIV, mitmHackedKey, mitmAIV)
                    }
                    p -> {
                        mitmHackedKey = BigInteger.ZERO.hash()
                        mitmHackedMessage = aesCbcDecrypt(mitmAIV, mitmHackedKey, mitmAIV)
                    }
                    else -> {

                        val candidates = listOf<BigInteger>(BigInteger.ONE, p.minus(BigInteger.ONE))

                        candidates.forEach { candidate ->
                            mitmHackedKey = candidate.hash()
                            mitmHackedMessage = aesCbcDecrypt(mitmAIV, mitmHackedKey, mitmAIV)
                        }

                    }

                }

                println("Message = MITM hacked message: ${message.toHex()} = ${mitmHackedMessage?.toHex()}")
                println(message.toHex() == mitmHackedMessage?.toHex())
            }

        }

    }

}
