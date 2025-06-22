package my.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class EncDecModule {

    private static Logger logger;
    private static int RETURN_CODE = 0;

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    	if(args.length < 3) {
    		System.out.println("==========================================================================");
    		System.out.println("                                                                          ");
    		System.out.println("Invalid arguments, [Properties file's fullpath] [ENCRYPT|DECRYPT] [String]");
    		System.out.println("                                                                          ");
    		System.out.println("==========================================================================");
    		RETURN_CODE = 1;
    		System.exit(RETURN_CODE);
    		return;
    	}

        logger = Logger.getLogger(EncDecModule.class.getName());
        FileHandler fh;
        try {

            // This block configure the logger with handler and formatter
        	Logger parentLog= logger.getParent();
            if (parentLog!=null && parentLog.getHandlers().length>0) parentLog.removeHandler(parentLog.getHandlers()[0]);
            
            fh = new FileHandler(args[0] + ".log", true);
            logger.addHandler(fh);
            SimpleFormatter formatter = new SimpleFormatter();
            fh.setFormatter(formatter);
            
            //logger.setLevel(Level.WARNING);

            // the following statement is used to log any messages
            //logger.info("My first log");

        } catch (SecurityException e) {
        	logger.severe(e.getMessage());
        	//e.printStackTrace();
        	RETURN_CODE = 1;
        	System.exit(RETURN_CODE);
            return;
        } catch (IOException e) {
        	logger.severe(e.getMessage());
        	//e.printStackTrace();
        	RETURN_CODE = 1;
        	System.exit(RETURN_CODE);
            return;
        }

        logger.info("==============Main Start");

        String keyFilePath =  args[0];
        String originalString = args[2];

        if("ENCRYPT".equals(args[1])) {
        	System.out.println(AES256.encrypt(keyFilePath, originalString));
        	if(RETURN_CODE == 0) RETURN_CODE = 0;
        }
        else if("DECRYPT".equals(args[1])) {
        	System.out.println(AES256.decrypt(keyFilePath, originalString));
        	if(RETURN_CODE == 0) RETURN_CODE = 0;
        }
        else {
        	logger.info("Invalid arguments!!!");
        	System.out.print("Invalid arguments!!!");
        	RETURN_CODE = 1;
        }

        logger.info("==============Main End");
        System.exit(RETURN_CODE);
        return;
    }

    private static class AES256 {
        private static String SECRET_KEY ="";
        private static String SALT = "";
        private static byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        //Random
        private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
        private static final String NUMBERS = "0123456789";
        // https://www.owasp.org/index.php/Password_special_characters
        private static final String SPECIAL = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        private static final String ALL = UPPERCASE + LOWERCASE + NUMBERS + SPECIAL;

        private static final SecureRandom random = new SecureRandom();

        private static String selectRandomTokens(int n, String tokens) {
            StringBuilder randomTokens = new StringBuilder();

            for (int i = 0; i < n; i++) {
                randomTokens.append(tokens.charAt(random.nextInt(tokens.length())));
            }
            return randomTokens.toString();
        }

        public static String generate(int nUppercase, int nLowercase, int nNumbers, int nSpecial, int maxlength) {
            int fill = maxlength - (nUppercase + nLowercase + nNumbers + nSpecial);
            if (fill < 0) {
            	logger.info("==============generate IllegalArgumentException");
            	RETURN_CODE = 1;
            	throw new IllegalArgumentException();
            }
            return shuffle(
                selectRandomTokens(nUppercase, UPPERCASE)
              + selectRandomTokens(nLowercase, LOWERCASE)
              + selectRandomTokens(nNumbers, NUMBERS)
              + selectRandomTokens(nSpecial, SPECIAL)
              + selectRandomTokens(fill, ALL)
            );
        }

        private static String shuffle(String s) {
            List<String> tokens = Arrays.asList(s.split(""));
            Collections.shuffle(tokens);
            return String.join("", tokens);
        }

        private static String base64Encoder(byte[] bytes) {
            return Base64.getEncoder().encodeToString(bytes);
        }

        private static byte[] base64Decoder(String bytes) {
            return Base64.getDecoder().decode(bytes);
        }

        private static void generateIv() {
            new SecureRandom().nextBytes(IV);
            return;
        }

        private static boolean makeKeyAndSaltAndIV(String keyFilePath) {
            logger.info("==============makeKeyAndSalt Start");

            //Backup and recreate a key file, if there is exist.
            try {
                OutputStream os = null;
                File propertiesFile = new File(keyFilePath);
                if(propertiesFile.exists()) {
                	propertiesFile.renameTo(new File(keyFilePath+(new SimpleDateFormat("yyyyMMddHHmmss").format(Calendar.getInstance().getTime()))));
                }
                propertiesFile.createNewFile();
                Properties p = new Properties();
                InputStream is = new FileInputStream(keyFilePath);
                p.load(is);
                SECRET_KEY = generate(5,5,5,0,20);
                p.setProperty("SECRET_KEY", SECRET_KEY);
                SALT = generate(5,5,5,0,15);
                p.setProperty("SALT", SALT);
                generateIv();
                p.setProperty("IV", base64Encoder(IV));
                os = new FileOutputStream(keyFilePath);
                p.store(os, null);
            } catch (IOException ioe) {
                logger.info(ioe.getMessage());
                RETURN_CODE = 1;
            	//ioe.printStackTrace(System.out);
            }
            logger.info("==============makeKeyAndSalt End");
            return true;
        }

        private static boolean getKeyAndSaltAndVI(String keyFilePath) {
            logger.info("==============getKeyAndSalt Start");

            // If there is no key file, Create a key file
            File f = new File(keyFilePath);
            if(!f.exists()) {
                logger.info("==============getKeyAndSalt Key File not exist");
                makeKeyAndSaltAndIV(keyFilePath);
            }

            logger.info("==============getKeyAndSalt Key File exist");

            try(FileInputStream fis = new FileInputStream(keyFilePath))
            {
                Properties info;
                info = new Properties();
                info.load(fis);
                SECRET_KEY = info.getProperty("SECRET_KEY");
                SALT = info.getProperty("SALT");
                IV = base64Decoder(info.getProperty("IV"));
            } catch(IOException ioe){
            	logger.info(ioe.getMessage());
            	RETURN_CODE = 1;
            	//ioe.printStackTrace(System.out);
            }
            logger.info("==============getKeyAndSalt End");

            return true;
        }

        private static String getKey() {
            logger.info("==============getKey Start");
            logger.info("==============getKey End");
            return SECRET_KEY;
        }

        private static String getSalt() {
            logger.info("==============getSalt Start");
            logger.info("==============getSalt End");
            return SALT;
        }

        private static String encrypt(String keyFilePath, String strToEncrypt) {
            logger.info("==============encrypt Start");

            if(!getKeyAndSaltAndVI(keyFilePath)) {
                logger.info("Key and Salt value read error!!");
                RETURN_CODE = 1;
                return null;
            }

            try {
                IvParameterSpec ivspec = new IvParameterSpec(IV);

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(getKey().toCharArray(), getSalt().getBytes(), 65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
                return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception e) {
                logger.info("Error while encrypting: " + e.toString());
                RETURN_CODE = 1;
            }
            logger.info("==============encrypt End");
            return null;
        }


        private static String decrypt(String keyFilePath, String strToDecrypt) {
            logger.info("==============decrypt Start");

            if(!getKeyAndSaltAndVI(keyFilePath)) {
                logger.info("Key and Salt value read error!!");
                RETURN_CODE = 1;
                return null;
            }

            try {
                IvParameterSpec ivspec = new IvParameterSpec(IV);

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(getKey().toCharArray(), getSalt().getBytes(), 65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
                return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
            } catch (Exception e) {
                logger.info("Error while decrypting: " + e.toString());
                RETURN_CODE = 1;
            }
            logger.info("==============decrypt End");
            return null;
        }

    }

}
