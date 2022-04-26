package encryptionAndDecryption.encryptEnum;

public enum RSAKeyEnum {
	/**
	 * 有向量加密模式, 不足8位用0补足8位, 需代码给加密内容添加0, 如{65,65,65,0,0,0,0,0}
	 */
	SLAT_KEY_LENGTH_512(512),
	/**
	 * 有向量加密模式, 不足8位用余位数补足8位, 如{65,65,65,5,5,5,5,5}或{97,97,97,97,97,97,2,2}; 刚好8位补8位8
	 */
	SLAT_KEY_LENGTH_1024(1024),
	/**
	 * 无向量加密模式, 不足8位用0补足8位, 需代码给加密内容添加0
	 */
	SLAT_KEY_LENGTH_2048(2048),
	/**
	 * 无向量加密模式, 不足8位用余位数补足8位
	 */
	SLAT_KEY_LENGTH_4096(4096),;

	RSAKeyEnum(int SLAT_KEY_LENGTH) {
		this.SLAT_KEY_LENGTH = SLAT_KEY_LENGTH;
	}

	private int SLAT_KEY_LENGTH;

	public int getSLAT_KEY_LENGTH() {
		return SLAT_KEY_LENGTH;
	}

	public void setSLAT_KEY_LENGTH(int SLAT_KEY_LENGTH) {
		this.SLAT_KEY_LENGTH = SLAT_KEY_LENGTH;
	}

	public static RSAKeyEnum getDigits(int digits){
		for (RSAKeyEnum value : RSAKeyEnum.values()) {
			if (value.getSLAT_KEY_LENGTH() == digits){
				return value;
			}
		}
		return RSAKeyEnum.SLAT_KEY_LENGTH_1024;
	}
}
