package encryptionAndDecryption.encryptEnum;

public enum MDEnum {
	MD2("MD2"),
	MD5("MD5");
	
	private MDEnum(String encryptType) {
		this.encryptType = encryptType;
	}

	private String encryptType;

	public String getEncryptType() {
		return encryptType;
	}

	public void setEncryptType(String encryptType) {
		this.encryptType = encryptType;
	}

	public static MDEnum getMode(String encryptionMode){
		MDEnum[] values = MDEnum.values();
		for (MDEnum value : values) {
			if (value.getEncryptType().equalsIgnoreCase(encryptionMode)) {
				return value;
			}
		}
		return MDEnum.MD5;
	}
}
