package task34

import DEFAULT_P
import aesCbcDecrypt
import aesCbcEncrypt
import hash
import iv
import message
import randomByteArray
import task33.DiffieHellman
import toHex
import java.math.BigInteger

class Main {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val p = DEFAULT_P
            val g = BigInteger("2", 16)

            val aliceDh = DiffieHellman(p, g)
            val bobDh = DiffieHellman(p, g)
            val aliceSharedKey = aliceDh.sharedKey(p)
            val bobSharedKey = bobDh.sharedKey(p)

            val message = "I can't do no wrong when I with my squad...".toByteArray()

            var iv = randomByteArray()
            val msgFromAliceEncrypted = aesCbcEncrypt(aliceSharedKey.hash(), iv, message) + iv

            val ivFromAlice = msgFromAliceEncrypted.iv()
            val msgFromAliceDecrypted = aesCbcDecrypt(bobSharedKey.hash(), ivFromAlice, msgFromAliceEncrypted.message())

            iv = randomByteArray()
            val msgFromBobEncrypted = aesCbcEncrypt(bobSharedKey.hash(), iv, msgFromAliceDecrypted) + iv

            val mitmKey = BigInteger.valueOf(0L)

            val ivAlice = msgFromAliceEncrypted.iv()
            val msgFromAliceHacked = aesCbcDecrypt(mitmKey.hash(), ivAlice, msgFromAliceEncrypted.message())

            val ivBob = msgFromBobEncrypted.iv()
            val msgFromBobHacked = aesCbcDecrypt(mitmKey.hash(), ivBob, msgFromBobEncrypted.message())

            println("Message: ${message.toHex()}")
            println("From Alice: ${msgFromAliceHacked.toHex()}")
            println("From Bob: ${msgFromBobHacked.toHex()}")
            println(message.toHex() == msgFromAliceHacked.toHex() && message.toHex() == msgFromBobHacked.toHex())
        }

    }

}
