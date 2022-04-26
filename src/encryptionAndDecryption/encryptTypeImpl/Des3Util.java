package encryptionAndDecryption.encryptTypeImpl;





import encryptionAndDecryption.encryptEnum.Des3Enum;
import encryptionAndDecryption.encryptEnum.MDEnum;
import encryptionAndDecryption.encryptImpl.CipherEencryptImp;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Des3加密工具类
 */
public class Des3Util extends CipherEencryptImp<Des3Enum, Des3Enum> {
	public Des3Util(Des3Enum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? Des3Enum.CBC_NO_PADDING : defaultEncrypt;
		String slat = EncryptUtil.MD_ENCRYPT.encryptHex(EncryptUtil.DES3_SLAT, EncryptUtil.DES3_SLAT, MDEnum.MD5);
		this.configSlat = slat.substring(0, 24);
		this.configVectorKey = slat.substring(24);
	}
	private final static String DESEDE_ALGORITHM_NAME = "DESede";
	private final static int SLAT_KEY_LENGTH = 24;
	private final static int VECTOR_KEY_LENGTH = 8;
	
	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, Des3Enum encryptType) throws Exception {
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
			SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), DESEDE_ALGORITHM_NAME);
			byte[] plaintext = null;
			if (Des3Enum.CBC_NO_PADDING.equals(encryptType) || Des3Enum.ECB_NO_PADDING.equals(encryptType))
			{
				plaintext = handleNoPaddingEncryptFormat(cipher, content);
			} 
			else 
			{
				plaintext = content.getBytes();
			}
			if (Des3Enum.CBC_NO_PADDING.equals(encryptType) || Des3Enum.CBC_PKCS5PADDING.equals(encryptType))
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
	protected byte[] encrypt(String content, String slatKey, String vectorKey, Des3Enum encryptType, Des3Enum encryptKey) throws Exception {
		return encrypt(content, slatKey, vectorKey, encryptType);
	}

	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, Des3Enum encryptType) throws Exception {
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
			SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), DESEDE_ALGORITHM_NAME);
			if (Des3Enum.CBC_NO_PADDING.equals(encryptType) || Des3Enum.CBC_PKCS5PADDING.equals(encryptType))
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
	protected String decrypt(byte[] content, String slatKey, String vectorKey, Des3Enum encryptType, Des3Enum encryptKey) throws Exception {
		return decrypt(content, slatKey, vectorKey, encryptType);
	}
}
