# maven中pom.xml中的依赖
<!--servlet包的依赖-->
  <dependency>
		  <groupId>javax.servlet</groupId>
		  <artifactId>javax.servlet-api</artifactId>
		  <version>3.1.0</version>
  </dependency>  
  
	<dependency>
   		 <groupId>org.testng</groupId>
   		 <artifactId>testng</artifactId>
      <version>6.14.2</version>
	</dependency>  
	
	<dependency>
		  <groupId>com.xiaoleilu</groupId>
		  <artifactId>hutool-all</artifactId>
		  <version>3.0.9</version>
	</dependency>
  ## 基于Cipher类实现的加密和解密
  import java.io.IOException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.testng.util.Strings;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
/**
 *	基于Cipher类实现的加密和解密工具类
 */
public class DeEnCoderCipherUtil {
	//加密、解密模式
	private final static String CIPHER_MODE = "DES";
	//DES密匙
	public static String DEFAULT_DFS_KEY = "区块链是分布式数据存储、点对点传输、共识机制、加密算法等计算机技术的新型应用模式。 ";
	/**
	 * 	function 加密通用方法
	 * 	@param key 加密密匙
	 * 	@return 密文
	 */
	public static  String encrypt(String originalContent, String key) {
		//明文或加密密匙为空时
		if(Strings.isNullOrEmpty(originalContent) || Strings.isNullOrEmpty(key)) {
			return null;
		}
		try {
			byte[] byteContent = encrypt(originalContent.getBytes(), key.getBytes());
			return new BASE64Encoder().encode(byteContent);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 *	function 解密通用方法
	 *
	 *	@param ciphertext
	 *	@param key DES解密密匙
	 *	@return 明文
	 */
	public static String decrypt(String ciphertext, String key) {
		//密文或加密密匙为空时
		if(Strings.isNullOrEmpty(ciphertext) || Strings.isNullOrEmpty(key)) {
			return null;
		}
		
		//密文或加密密匙不为空时
		try {
			BASE64Decoder decoder = new BASE64Decoder();
			byte[] bufCiphertext = decoder.decodeBuffer(ciphertext);
			byte[] contentByte = decrypt(bufCiphertext, key.getBytes());
			return new String(contentByte);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 *	function字节加密方法
	 *	
	 *	@param originalContent: 明文
	 *	@param key 加密密匙的byte数组
	 *	@return 密文的byte数组
	 */
	private static byte[] encrypt(byte[] originalContent, byte[] key) throws Exception {
		//1..生成可信任的随机数源
		SecureRandom secureRandom = new SecureRandom();
		//2..基于密匙数据创建DESKeySpec(key)对象
		DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
		//3..创建密匙工厂,将DESKeySpec转换成SecretKey对象来保存对称密匙
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CIPHER_MODE);
		SecretKey secureKey = keyFactory.generateSecret(desKeySpec);
		//4..Cipher对象时间完成加密操作，指定其支持指定的加密和解密算法
		Cipher cipher = Cipher.getInstance(CIPHER_MODE);
		//5..用密匙初始化Cipher对象，ENCRYPT_MODE 表示加密模式
		cipher.init(Cipher.ENCRYPT_MODE, secureKey, secureRandom);
		//返回密文
		return cipher.doFinal(originalContent);
	}
	
	/**
	 * 	function字节解密方法
	 * 	
	 * @param ciphertextByte:字节密文
	 * @param key 解密密匙（同加密密匙）byte数组
	 * @return 明文byte数组
	 */
	
	private static byte[] decrypt(byte[] ciphertextByte, byte[] key) throws Exception {
		//1..生成可信任的随机数源
		SecureRandom secureRandom = new SecureRandom();
		//2..从原始密匙数据创建DESKeySpec对象
		DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
		//3..创建密匙工厂,将DESKeySpec转换成SecretKey对象来保存对称密匙
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CIPHER_MODE);
		SecretKey secureKey = keyFactory.generateSecret(desKeySpec);
		//4..Cipher对象实际完成解密操作，指定其支持响应的加密和解密算法
		Cipher cipher = Cipher.getInstance(CIPHER_MODE);
		//5..用密匙初始化Cipher对象，DECRYPT_MODE 表示解密模式
		cipher.init(Cipher.DECRYPT_MODE, secureKey, secureRandom);
		//6..返回明文
		return cipher.doFinal(ciphertextByte);
	}
}
## 基于Hutool工具类的加密解密类 
import java.security.PrivateKey;
import java.security.PublicKey;
import org.testng.util.Strings;

import com.xiaoleilu.hutool.crypto.SecureUtil;
import com.xiaoleilu.hutool.crypto.asymmetric.KeyType;
import com.xiaoleilu.hutool.crypto.asymmetric.RSA;
import com.xiaoleilu.hutool.crypto.symmetric.DES;

/**
 * 	基于Hutool工具类的加密解密类 
 *
 */
public class DeEnCoderHutoolUtil {
	
	//构建RSA对象
	private static RSA rsa = new RSA();
	//获得私钥
	private static PrivateKey privateKey = rsa.getPrivateKey();
	//获得公钥
	private static PublicKey publicKey = rsa.getPublicKey();
	
	/**
	 * 	function RSA加密通用算法:对称加密解密
	 * 	
	 * 	@param originalContent:明文
	 * 	@return 密文
	 */
	public static String rsaEncrypt(String originalContent) {
		//明文或加密密钥为空时
		if(Strings.isNullOrEmpty(originalContent)) {
			return null;
		}
		//公钥加密，之后私钥解密
		return  rsa.encryptStr(originalContent, KeyType.PublicKey);	
	}
	
	/**
	 * 	function RSA解密通用方法:对称加密解密
	 * 
	 * 	@param ciphertext 密文
	 * 	@param key RSA解密密钥(同加密密钥)
	 * 	@return 明文
	 */
	public static String rsaDecrypt(String ciphertext) {
		if(Strings.isNullOrEmpty(ciphertext)) {
			return null;
		}
		return rsa.decryptStr(ciphertext, KeyType.PrivateKey);
	}
	
	/**
	 * 	function DES加密通用方法:对称加密解密
	 * 
	 * 	@param originalContent:明文
	 * 	@param key 加密密匙
	 *  @param 密文
	 */
	public static String desEncrypt(String originalContent, String key) {
		//明文或加密密匙为空时
		if(Strings.isNullOrEmpty(originalContent) || Strings.isNullOrEmpty(key)) {
			return null;
		}
		
		//还可以随机生成密匙
		//byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.DES.getValue()).getEncoded();
		
		//构建
		DES des = SecureUtil.des(key.getBytes());
		
		//加密
		return des.encryptHex(originalContent);
	}
	
	/**
	 * 	function DES 解密通用方法:对称加密解密
	 * 	
	 *  @param ciphertext 密文
	 *  @param key DES 解密密钥(同加密密钥)
	 * 	@return 明文
	 */
	public static String desDecrypt(String ciphertext, String key) {
		//密文或加密密钥为空时
		if(Strings.isNullOrEmpty(ciphertext) || Strings.isNullOrEmpty(key)) {
			return null;
		}
		
		//还可以随机生成密钥
		//byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.DES.getValue()).getEncoded();
		
		
		//构建
		DES des = SecureUtil.des(key.getBytes());
		//解密
		return des.decryptStr(ciphertext);
	}
}
