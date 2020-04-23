package task33

import DEFAULT_P
import java.math.BigInteger

class Main {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val p = DEFAULT_P
            val g = BigInteger("2", 16)
            val aliceDH = DiffieHellman(p, g)
            val bobDH = DiffieHellman(p, g)

            val alicePublicKey = aliceDH.publicKey()
            val bobPublicKey = bobDH.publicKey()

            val aliceSharedKey = aliceDH.sharedKey(bobPublicKey)
            val bobSharedKey = bobDH.sharedKey(alicePublicKey)


            println("Alice's key = Bob's key: ${aliceSharedKey == bobSharedKey}")
        }
    }

}
