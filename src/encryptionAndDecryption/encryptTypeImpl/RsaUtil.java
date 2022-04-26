package encryptionAndDecryption.encryptTypeImpl;





import encryptionAndDecryption.encryptEnum.RSAEnum;
import encryptionAndDecryption.encryptEnum.RSAKeyEnum;
import encryptionAndDecryption.encryptImpl.CipherEencryptImp;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * <p>RSA加密工具类，使用公匙加密，私匙解密</p>
 * <p>该工具类使用slatKey作为SecureRandom的随机种子来创建公匙和私匙，此情况下只需记录下slatKey即可</p>
 * <p>若需要使用 new SecureRandom() 来创建公匙和私匙，则创建公匙和私匙时，需要记录下公匙和私匙</p>
 * <p>RSA加密算法，一般有：1)使用公匙加密，需要使用私匙解密；2)使用私匙加密，需要使用公匙解密</p>
 */
public class RsaUtil extends CipherEencryptImp<RSAEnum, RSAKeyEnum> {
	public RsaUtil(RSAEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt;
		this.configSlat = EncryptUtil.RSA_SLAT;
	}
	private final static String RSA_ALGORITHM_NAME = "RSA";
	private final static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, RSAEnum encryptType) throws Exception {
		return encrypt(content, slatKey, vectorKey, encryptType, RSAKeyEnum.SLAT_KEY_LENGTH_1024);
	}
	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, RSAEnum encryptType, RSAKeyEnum RSAKeyEnum) throws Exception {
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
			byte[] decoded = getPublicKey(slatKey, RSAKeyEnum);
			RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(RSA_ALGORITHM_NAME).generatePublic(new X509EncodedKeySpec(decoded));
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			encrypted = cipher.doFinal(content.getBytes());
		} catch (Exception e) {
			throw new Exception(encryptException);
		}
		return encrypted;
	}


	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, RSAEnum encryptType) throws Exception {
		return decrypt(content, slatKey, vectorKey, encryptType, RSAKeyEnum.SLAT_KEY_LENGTH_1024);
	}

	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, RSAEnum encryptType, RSAKeyEnum RSAKeyEnum) throws Exception {
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
			byte[] decoded = getPrivateKey(slatKey, RSAKeyEnum);
			RSAPrivateKey pubKey = (RSAPrivateKey) KeyFactory.getInstance(RSA_ALGORITHM_NAME).generatePrivate(new PKCS8EncodedKeySpec(decoded));
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] original = cipher.doFinal(content);
			result = new String(original).trim();
		} catch (Exception e) {
			throw new Exception(encryptException);
		}
		return result;
	}
	
	/**
	 * 根据slatKey获取公匙，传入的slatKey作为SecureRandom的随机种子
	 * 若使用new SecureRandom()创建公匙，则需要记录下私匙，解密时使用
	 */
	private static byte[] getPublicKey(String slatKey, RSAKeyEnum RSAKeyEnum) throws Exception {
		KeyPairGenerator keyPairGenerator  = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
		random.setSeed(slatKey.getBytes());
		keyPairGenerator.initialize(RSAKeyEnum.getSLAT_KEY_LENGTH(), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair.getPublic().getEncoded();
	}
	
	/**
	 * 根据slatKey获取私匙，传入的slatKey作为SecureRandom的随机种子
	 */
	private static byte[] getPrivateKey(String slatKey, RSAKeyEnum RSAKeyEnum) throws Exception {
		KeyPairGenerator keyPairGenerator  = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
		random.setSeed(slatKey.getBytes());
		keyPairGenerator.initialize(RSAKeyEnum.getSLAT_KEY_LENGTH(), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair.getPrivate().getEncoded();
	}
}
