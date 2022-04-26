package encryptionAndDecryption.encryptTypeImpl;






import encryptionAndDecryption.encryptEnum.DesEnum;
import encryptionAndDecryption.encryptEnum.MDEnum;
import encryptionAndDecryption.encryptImpl.CipherEencryptImp;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * DES加密工具类
 */
public class DesUtil extends CipherEencryptImp<DesEnum, DesEnum> {
	public DesUtil(DesEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? DesEnum.CBC_NO_PADDING : defaultEncrypt;
		String slat = EncryptUtil.MD_ENCRYPT.encryptHex(EncryptUtil.DES_SLAT, EncryptUtil.DES_SLAT, MDEnum.MD5);
		this.configSlat = slat.substring(0, 8);
		this.configVectorKey = slat.substring(24);
	}
	private final static int SLAT_KEY_LENGTH = 8;
	private final static int VECTOR_KEY_LENGTH = 8;
	private final static String DES_ALGORITHM_NAME = "DES";
	
	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, DesEnum encryptType) throws Exception {
		byte[] encrypted = null;
		try {
			if (slatKey == null || slatKey.length() != SLAT_KEY_LENGTH) 
			{
				throw new Exception("slatKey is null or slatKey is not at " + SLAT_KEY_LENGTH + "-bytes.");
			}
			if (encryptType == null)
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), DES_ALGORITHM_NAME);
			byte[] plaintext = null;
			if (DesEnum.CBC_NO_PADDING.equals(encryptType) || DesEnum.ECB_NO_PADDING.equals(encryptType))
			{
				plaintext = handleNoPaddingEncryptFormat(cipher, content);
			} 
			else 
			{
				plaintext = content.getBytes();
			}
			if (DesEnum.CBC_NO_PADDING.equals(encryptType) || DesEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (vectorKey == null || vectorKey.length() != VECTOR_KEY_LENGTH) 
				{
					throw new Exception("vectorKey is null or vectorKey is not at " + VECTOR_KEY_LENGTH + "-bytes.");
				}
				IvParameterSpec iv = new IvParameterSpec(vectorKey.getBytes());
				cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
			} 
			else 
			{
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			}
			encrypted = cipher.doFinal(plaintext);
		} catch (Exception e) {
			throw new Exception(encryptException);
		}
		return encrypted;
	}

	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, DesEnum encryptType, DesEnum encryptKey) throws Exception {
		return encrypt(content, slatKey, vectorKey, encryptType);
	}

	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, DesEnum encryptType) throws Exception {
		String result = null;
		try {
			if (slatKey == null || slatKey.length() != SLAT_KEY_LENGTH) 
			{
				throw new Exception("slatKey is null or slatKey is not at " + SLAT_KEY_LENGTH + "-bytes.");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), DES_ALGORITHM_NAME);
			if (DesEnum.CBC_NO_PADDING.equals(encryptType) || DesEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (vectorKey == null || vectorKey.length() != VECTOR_KEY_LENGTH) 
				{
					throw new Exception("vectorKey is null or vectorKey is not at " + VECTOR_KEY_LENGTH + "-bytes.");
				}
				IvParameterSpec iv = new IvParameterSpec(vectorKey.getBytes());
				cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
			} 
			else 
			{
				cipher.init(Cipher.DECRYPT_MODE, secretKey);
			}
			byte[] original = cipher.doFinal(content);
			String originalString = new String(original);
			result = originalString.trim();
		} catch (Exception e) {
			throw new Exception(decryptException);
		}
		return result;
	}

	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, DesEnum encryptType, DesEnum encryptKey) throws Exception {
		return decrypt(content, slatKey, vectorKey, encryptType);
	}
}
