package encryptionAndDecryption.encryptTypeImpl;






import encryptionAndDecryption.encryptEnum.ShaEnum;
import encryptionAndDecryption.encryptImpl.MessageDigestImp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA摘要加密
 */
public class ShaUtil extends MessageDigestImp<ShaEnum> {
	public ShaUtil(ShaEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? ShaEnum.SHA256 : defaultEncrypt;
		this.configSlat = EncryptUtil.SHA_SLAT;
	}
	
	@Override
	protected byte[] encrypt(String content, String slat, ShaEnum encryptType) {
		try {
			String encryptContent = content + slat;
			MessageDigest messageDigest = MessageDigest.getInstance(encryptType.getEncryptType());
			return messageDigest.digest(encryptContent.getBytes());
		} catch (NoSuchAlgorithmException e) {
		}
		return null;
	}
}
