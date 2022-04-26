package encryptionAndDecryption.encryptTypeImpl;




import encryptionAndDecryption.encryptEnum.AesEnum;
import encryptionAndDecryption.encryptEnum.AesKeyEnum;
import encryptionAndDecryption.encryptImpl.CipherEencryptImp;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;


/**
 * AES加密实现，key使用类KeyGenerator获取，与使用new SecretKeySpec()获取key的优点是传入的key长度可以是任意的，不需要固定16位byte
 * 
 * 若出现 异常：Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
 * 属于解密失败，原因可能是传入的slatKey或者vectorKey与加密时使用的不一致
 */
public class AesKgenUtil extends CipherEencryptImp<AesEnum, AesKeyEnum> {
	public AesKgenUtil(AesEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? AesEnum.CBC_NO_PADDING : defaultEncrypt;
		this.configSlat = EncryptUtil.AES_SLAT;
		this.configVectorKey = EncryptUtil.AES_SLAT;
	}
	private final static String AES_ALGORITHM_NAME = "AES";
	private final static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, AesEnum encryptType) throws Exception {
		return encrypt(content, slatKey, vectorKey, encryptType, AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_128);
	}
	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, AesEnum encryptType, AesKeyEnum aesKeyEnum) throws Exception {
		byte[] encrypted = null;
		try {
			if (slatKey == null) 
			{
				throw new Exception("slatKey is null");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			Key key = getSlatKey(slatKey, aesKeyEnum);
			byte[] plaintext = null;
			if (AesEnum.CBC_NO_PADDING.equals(encryptType) || AesEnum.ECB_NO_PADDING.equals(encryptType))
			{
				plaintext = handleNoPaddingEncryptFormat(cipher, content);
			} else {
				plaintext = content.getBytes();
			}
			if (AesEnum.CBC_NO_PADDING.equals(encryptType) || AesEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (vectorKey == null) 
				{
					throw new Exception("vectorKey is null");
				}
				IvParameterSpec iv = getVectorKey(vectorKey, aesKeyEnum);
				cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			} 
			else 
			{
				cipher.init(Cipher.ENCRYPT_MODE, key);
			}
			encrypted = cipher.doFinal(plaintext);
		} catch (Exception e) {
			throw new Exception(encryptException);
		}
		return encrypted;
	}
	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, AesEnum encryptType) throws Exception {
		return decrypt(content, slatKey, vectorKey, encryptType, AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_128);
	}
	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, AesEnum encryptType, AesKeyEnum aesKeyEnum) throws Exception {
		String result = null;
		try {
			if (slatKey == null) 
			{
				throw new Exception("slatKey is null");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			Key key = getSlatKey(slatKey, aesKeyEnum);
			if (AesEnum.CBC_NO_PADDING.equals(encryptType) || AesEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (vectorKey == null) 
				{
					throw new Exception("vectorKey is null");
				}
				IvParameterSpec iv = getVectorKey(vectorKey, aesKeyEnum);
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
			}
			else 
			{
				cipher.init(Cipher.DECRYPT_MODE, key);
			}
			byte[] original = cipher.doFinal(content);
			result = new String(original).trim();
		} catch (Exception e) {
			throw new Exception(decryptException);
		}
		return result;
	}

	/**
	 * 获取加密的密匙，传入的slatKey可以是任意长度的，作为SecureRandom的随机种子，
	 * 而在KeyGenerator初始化时设置密匙的长度128bit(16位byte)
	 */
	private static Key getSlatKey(String slatKey, AesKeyEnum aesKeyEnum) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
		random.setSeed(slatKey.getBytes());
		kgen.init(aesKeyEnum.getSLAT_KEY_LENGTH(), random);
		Key key = kgen.generateKey();
		return key;
	}

	/**
	 * 获取加密的向量
	 */
	private static IvParameterSpec getVectorKey(String vectorKey, AesKeyEnum aesKeyEnum) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
		random.setSeed(vectorKey.getBytes());
		kgen.init(aesKeyEnum.getVECTOR_KEY_LENGTH(), random);
		IvParameterSpec iv = new IvParameterSpec(kgen.generateKey().getEncoded());
		return iv;
	}
}
