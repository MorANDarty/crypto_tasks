import java.math.BigInteger
import java.security.MessageDigest
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

val DEFAULT_P = BigInteger(
    "fafafafafafafafac90fdaa22168c234c4c6628b80dc1cd129024" +
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
            "fffffffffffff", 16
)

val DEFAULT_G = BigInteger("2", 16)

fun randomByteArray(size: Int = 16): ByteArray = ByteArray(size).apply { Random().nextBytes(this) }

fun aesCbcEncrypt(key: ByteArray, iv: ByteArray, msg: ByteArray): ByteArray =
    Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }.doFinal(msg)

fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, msg: ByteArray): ByteArray =
    Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }.doFinal(msg)

fun BigInteger.hash(): ByteArray {
    val messageDigest = MessageDigest.getInstance("SHA-1")
    messageDigest.update(toByteArray())
    return messageDigest.digest()
        .take(16)
        .toByteArray()
}

fun ByteArray.toHex(): String = BigInteger(this).toString(16)

fun ByteArray.message() = this.dropLast(16).toByteArray()

fun ByteArray.iv() = this.takeLast(16).toByteArray()
