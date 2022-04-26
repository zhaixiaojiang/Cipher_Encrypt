package encryptionAndDecryption.encryptEnum;

public enum AesKeyEnum {
	/**
	 * 128位密钥
	 */
	SLAT_VECTOR_KEY_LENGTH_128(128, 128, 16, 16),
	/**
	 * 192位密钥
	 */
	SLAT_VECTOR_KEY_LENGTH_192(192, 192, 24, 24),
	/**
	 * 256位密钥
	 */
	SLAT_VECTOR_KEY_LENGTH_256(256, 256, 32, 32);

	AesKeyEnum(int SLAT_KEY_LENGTH, int VECTOR_KEY_LENGTH, int SLAT_KEY_LENGTH_BYTES, int VECTOR_KEY_LENGTH_BYTES) {
		this.SLAT_KEY_LENGTH = SLAT_KEY_LENGTH;
		this.VECTOR_KEY_LENGTH = VECTOR_KEY_LENGTH;
		this.SLAT_KEY_LENGTH_BYTES = SLAT_KEY_LENGTH_BYTES;
		this.VECTOR_KEY_LENGTH_BYTES = VECTOR_KEY_LENGTH_BYTES;
	}

	private int SLAT_KEY_LENGTH;
	private int VECTOR_KEY_LENGTH;
	private int SLAT_KEY_LENGTH_BYTES;
	private int VECTOR_KEY_LENGTH_BYTES;

	public int getSLAT_KEY_LENGTH() {
		return SLAT_KEY_LENGTH;
	}

	public void setSLAT_KEY_LENGTH(int SLAT_KEY_LENGTH) {
		this.SLAT_KEY_LENGTH = SLAT_KEY_LENGTH;
	}

	public int getVECTOR_KEY_LENGTH() {
		return VECTOR_KEY_LENGTH;
	}

	public void setVECTOR_KEY_LENGTH(int VECTOR_KEY_LENGTH) {
		this.VECTOR_KEY_LENGTH = VECTOR_KEY_LENGTH;
	}

	public int getSLAT_KEY_LENGTH_BYTES() {
		return SLAT_KEY_LENGTH_BYTES;
	}

	public void setSLAT_KEY_LENGTH_BYTES(int SLAT_KEY_LENGTH_BYTES) {
		this.SLAT_KEY_LENGTH_BYTES = SLAT_KEY_LENGTH_BYTES;
	}

	public int getVECTOR_KEY_LENGTH_BYTES() {
		return VECTOR_KEY_LENGTH_BYTES;
	}

	public void setVECTOR_KEY_LENGTH_BYTES(int VECTOR_KEY_LENGTH_BYTES) {
		this.VECTOR_KEY_LENGTH_BYTES = VECTOR_KEY_LENGTH_BYTES;
	}

	public static AesKeyEnum getDigits(int digits){
		for (AesKeyEnum value : AesKeyEnum.values()) {
			if (value.getSLAT_KEY_LENGTH() == digits){
				return value;
			}
		}
		return AesKeyEnum.SLAT_VECTOR_KEY_LENGTH_128;
	}
}
