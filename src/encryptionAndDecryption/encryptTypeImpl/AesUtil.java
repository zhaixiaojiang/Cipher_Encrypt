package encryptionAndDecryption.encryptTypeImpl;




import encryptionAndDecryption.encryptEnum.AesEnum;
import encryptionAndDecryption.encryptEnum.AesKeyEnum;
import encryptionAndDecryption.encryptEnum.MDEnum;
import encryptionAndDecryption.encryptImpl.CipherEencryptImp;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密工具类
 */
public class AesUtil extends CipherEencryptImp<AesEnum, AesKeyEnum> {
	public AesUtil(AesEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? AesEnum.CBC_NO_PADDING : defaultEncrypt;
		String slat = EncryptUtil.MD_ENCRYPT.encryptHex(EncryptUtil.AES_SLAT, EncryptUtil.AES_SLAT, MDEnum.MD5);
		this.configSlat = slat.substring(0, 16);
		this.configVectorKey = slat.substring(16);
	}
	private final static String AES_ALGORITHM_NAME = "AES";

	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, AesEnum encryptType) throws Exception {
		byte[] encrypted = null;
		try {
			if (!checkSlatKey(slatKey))
			{
				throw new Exception("slatKey is null or slatKey is not at 16 or 24 or 32-bytes.");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), AES_ALGORITHM_NAME);
			byte[] plaintext = null;
			if (AesEnum.CBC_NO_PADDING.equals(encryptType) || AesEnum.ECB_NO_PADDING.equals(encryptType))
			{
				plaintext = handleNoPaddingEncryptFormat(cipher, content);
			} 
			else 
			{
				plaintext = content.getBytes();
			}
			if (AesEnum.CBC_NO_PADDING.equals(encryptType) || AesEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (!checkVectorKey(vectorKey))
				{
					throw new Exception("vectorKey is null or vectorKey is not at 16 or 24 or 32-bytes.");
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
	protected byte[] encrypt(String content, String slatKey, String vectorKey, AesEnum encryptType, AesKeyEnum encryptKey) throws Exception {
		return encrypt(content, slatKey, vectorKey, encryptType);
	}

	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, AesEnum encryptType) throws Exception {
		String result = null;
		try {
			if (!checkSlatKey(slatKey))
			{
				throw new Exception("slatKey is null or slatKey is not at 16 or 24 or 32-bytes.");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), AES_ALGORITHM_NAME);
			if (AesEnum.CBC_NO_PADDING.equals(encryptType) || AesEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (!checkVectorKey(vectorKey))
				{
					throw new Exception("vectorKey is null or vectorKey is not at 16 or 24 or 32-bytes.");
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
	protected String decrypt(byte[] content, String slatKey, String vectorKey, AesEnum encryptType, AesKeyEnum encryptKey) throws Exception {
		return decrypt(content, slatKey, vectorKey, encryptType);
	}

	protected boolean checkSlatKey(String slatKey){
		if (slatKey == null){
			return false;
		}
		if (slatKey.length() == AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_128.getSLAT_KEY_LENGTH_BYTES()){
			return true;
		}
		if (slatKey.length() == AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_192.getSLAT_KEY_LENGTH_BYTES()){
			return true;
		}
		if (slatKey.length() == AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_256.getSLAT_KEY_LENGTH_BYTES()){
			return true;
		}
		return false;
	}
	protected boolean checkVectorKey(String vectorKey){
		if (vectorKey == null){
			return false;
		}
		if (vectorKey.length() == AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_128.getVECTOR_KEY_LENGTH_BYTES()){
			return true;
		}
		if (vectorKey.length() == AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_192.getVECTOR_KEY_LENGTH_BYTES()){
			return true;
		}
		if (vectorKey.length() == AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_256.getVECTOR_KEY_LENGTH_BYTES()){
			return true;
		}
		return false;
	}
}
