import encryptionAndDecryption.encryptEnum.AesEnum;
import encryptionAndDecryption.encryptTypeImpl.EncryptUtil;

/**
 * @Description:
 * @Package PACKAGE_NAME
 * @Author Zhai Quanjiang
 * @Date 2022/4/26 10:46
 * @Version: V1.0
 * @Other:
 */
public class Test {
    public static void main(String[] args) throws Exception {
        String content = "D01F275F19EC2A28373B2E70F7A15CBB";
        String encryptBase64 = EncryptUtil.AES_ENCRYPT.encryptBase64(content, "1234567887654321", null, AesEnum.ECB_PKCS5PADDING);
        System.out.println(encryptBase64);
        String base64 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64(content, "1234567887654321", null, AesEnum.ECB_PKCS5PADDING);
        System.out.println(base64);
        System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(encryptBase64, "1234567887654321", null, AesEnum.ECB_PKCS5PADDING));
        System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(base64, "1234567887654321", null, AesEnum.ECB_PKCS5PADDING));
    }
}
