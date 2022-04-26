package encryptionAndDecryption.encryptTypeImpl;





import encryptionAndDecryption.encryptEnum.MDEnum;
import encryptionAndDecryption.encryptImpl.MessageDigestImp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD加密工具类
 */
public class MDUtil extends MessageDigestImp<MDEnum> {
	
	public MDUtil(MDEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? MDEnum.MD5 : defaultEncrypt;
		this.configSlat = EncryptUtil.MD_SLAT;
	}
	
	@Override
	protected byte[] encrypt(String content, String slat, MDEnum encryptType) {
		try {
			String encryptContent = null;
			if (slat != null)
			{
				encryptContent = content + slat;
			}
			else
			{
				encryptContent = content;
			}
			MessageDigest messageDigest = MessageDigest.getInstance(encryptType.getEncryptType());
			return messageDigest.digest(encryptContent.getBytes());
		} catch (NoSuchAlgorithmException e) {
		}
		return null;
	}
}
