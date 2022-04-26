package encryptionAndDecryption.encryptTypeImpl;

import encryptionAndDecryption.encryptEnum.*;
import encryptionAndDecryption.encryptImpl.ICipherEncrypt;
import encryptionAndDecryption.encryptImpl.IMessageDigest;

/**
 * 加密算法工具类
 */
public class EncryptUtil {
	public static String MD_SLAT = "test";
	
	public static String SHA_SLAT = "test";
	
	public static String AES_SLAT = "test";
	
	public static String DES_SLAT = "test";
	
	public static String DES3_SLAT = "test";
	
	public static String RSA_SLAT = "test";
	
	public final static IMessageDigest<MDEnum> MD_ENCRYPT = new MDUtil(MDEnum.MD5);
	
	public final static IMessageDigest<ShaEnum> SHA_ENCRYPT = new ShaUtil(ShaEnum.SHA256);


	
	public final static ICipherEncrypt<AesEnum, AesKeyEnum> AES_ENCRYPT = new AesUtil(AesEnum.CBC_NO_PADDING);
	
	public final static ICipherEncrypt<DesEnum, DesEnum> DES_ENCRYPT = new DesUtil(DesEnum.CBC_NO_PADDING);
	
	public final static ICipherEncrypt<Des3Enum, Des3Enum> DES3_ENCRYPT = new Des3Util(Des3Enum.CBC_NO_PADDING);
	
	public final static ICipherEncrypt<AesEnum, AesKeyEnum> AES_KGEN_ENCRYPT = new AesKgenUtil(AesEnum.CBC_NO_PADDING);
	
	public final static ICipherEncrypt<RSAEnum, RSAKeyEnum> RSA_ENCRYPT = new RsaUtil(RSAEnum.ECB_PKCS1PADDING);
}
