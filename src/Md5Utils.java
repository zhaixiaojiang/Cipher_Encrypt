

import java.security.MessageDigest;

/**
 * @Description:
 * @Package com.apexsoft.crm.workflow.utils.encrypt
 * @Author Zhai Quanjiang
 * @Date 2022/4/8 11:32
 * @Version: V1.0
 * @Other:
 */
public class Md5Utils {
    /**
     * Md5消息摘要加密
     * @param source
     * @param isUpper
     * @return
     */
    public static String md5(String source, boolean isUpper) {
        StringBuffer sb = new StringBuffer(32);
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] array = md.digest(source.getBytes("utf-8"));
            for (int i = 0; i < array.length; i++) {
                //MD5取值是否使用大写字母
                if (isUpper) {
                    sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).toUpperCase().substring(1, 3));
                } else {
                    sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
                }
            }
        } catch (Exception e) {
        }
        return sb.toString();
    }
}
