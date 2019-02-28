import java.util.Scanner;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.io.*; 
import javax.crypto.spec.*;
import java.security.*;
import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


class Proyect{
	static long timeMd = 0;
	static long timeS1=0;
	static long timeS2=0;;
	public static String getRSA_OAEP(String input, String key){
		byte[] k =  DatatypeConverter.parseHexBinary(key);	
		try{
			//byte[] inp = input.getBytes();
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "RSA");
			Cipher c = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
			c.init(Cipher.ENCRYPT_MODE, skeySpec);
			byte[] msg = c.doFinal(DatatypeConverter.parseHexBinary(input));
			BigInteger no = new BigInteger(1, msg); 
	        String ciphertext = no.toString(16).toUpperCase();
	        return ciphertext;
		}catch(Exception e){
			return null;
		}

	}

	public static String getAES256(String input, String key){
		SecureRandom random = new SecureRandom();
		byte[] k =  DatatypeConverter.parseHexBinary(key);
		byte bytes[] = new byte[20];
    	random.nextBytes(bytes);
    	byte[] saltBytes = bytes;
		try{
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			PBEKeySpec  spec = new PBEKeySpec(key.toCharArray(), saltBytes, 100, 256);
			//SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			Cipher c = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			c.init(Cipher.ENCRYPT_MODE, secretKey);

			byte[] msg = c.doFinal(DatatypeConverter.parseHexBinary(input));
	        BigInteger no = new BigInteger(1, msg); 
	        String ciphertext = no.toString(16).toUpperCase();
	        return ciphertext;


		}catch(Exception e){
			System.out.println("Erros: "+e);
			return null;
		}
	}
	public static String getAES(String input, String key){
		byte[] k =  DatatypeConverter.parseHexBinary(key);
		try{
			/*DESKeySpec dks = new DESKeySpec(k);
          //  SecretKeyFactory skf = SecretKeyFactory.getInstance("AES");
            SecretKey sk = dks.;
            */
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
	        Cipher c = Cipher.getInstance("AES/ECB/PKCS5PADDING");
	        c.init(Cipher.ENCRYPT_MODE, skeySpec);
	        //String m = "0000000000000000";
	        byte[] msg = c.doFinal(DatatypeConverter.parseHexBinary(input));
	        BigInteger no = new BigInteger(1, msg); 
	        String ciphertext = no.toString(16).toUpperCase();
	        return ciphertext;
		}catch(Exception e){
			System.out.println("Erros: "+e);
			return null;
		}
	}
	public static String getDES(String input, String key){
		byte[] k =  DatatypeConverter.parseHexBinary(key); 
		try{
            DESKeySpec dks = new DESKeySpec(k);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey sk = skf.generateSecret(dks);
	        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
	        c.init(Cipher.ENCRYPT_MODE, sk);
	        //String m = "0000000000000000";
	        byte[] msg = c.doFinal(DatatypeConverter.parseHexBinary(input));
	        BigInteger no = new BigInteger(1, msg); 
	        String ciphertext = no.toString(16).toUpperCase(); 

	        //System.out.println(new String(b));
	       // System.out.println(ciphertext);
	       
	        //c.init(Cipher.DECRYPT_MODE, sk);
	        //System.out.println(new String(c.doFinal(b)));
	         return ciphertext;
        }
        catch(Exception e)

        {
            System.out.println(e.getMessage());
            return null; 
        }   

	}

	public static String getSHA2(String input) 
    { 
  
        try { 
  	
            // Static getInstance method is called with hashing SHA 
            MessageDigest md = MessageDigest.getInstance("SHA-256"); 
  			long start = System.currentTimeMillis(); 
            // digest() method called 
            // to calculate message digest of an input 
            // and return array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
  			long end = System.currentTimeMillis(); 
  			timeS2 = end - start;

  			/*System.out.println("SHA-2 result: "+hashtext);
           
        	System.out.println("SHA-2 takes " + 
       	                             (end - start) + "ms");*/
            return hashtext; 
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown"
                               + " for incorrect algorithm: " + e); 
  
            return null; 
        } 
    } 

	 public static String getSHA1(String input) 
    { 
        try { 
        	long start = System.currentTimeMillis(); 
            //System.out.println("START: "+start);
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
  
            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            // Add preceding 0s to make it 32 bit 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
  
            // return the HashText 
            long end = System.currentTimeMillis(); 
          /*  System.out.println("end: "+end);
           System.out.println("SHA-1 result: "+hashtext);
           
        	System.out.println("SHA-1 takes " + 
       	                             (end - start) + "ms");*/
       	                            timeS1 = end - start;
        	return hashtext;
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 

	public static String getMd5(String input) 
    { 
        try { 
  			long start = System.currentTimeMillis(); 
  			//System.out.println("START: "+start);
            // Static getInstance method is called with hashing MD5 
            MessageDigest md = MessageDigest.getInstance("MD5"); 
  
            // digest() method is called to calculate message digest 
            //  of an input digest() return array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
            //return hashtext; 
             long end = System.currentTimeMillis();
             /*System.out.println("end: "+end); 
            System.out.println("MD5 result: "+hashtext);
           
        	System.out.println("MD5 takes " + 
       	                             (end - start) + "ms"); */
       	                             timeMd = end - start;
        	return hashtext;
        }  
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 

	public static void main(String[] args) {
		Scanner stdin = new Scanner(System.in);
		
		int opt;
		String algo = "";
		do{
			System.out.println("Select an option:");
			System.out.println("\n");
			System.out.println("1. Block ciphers: DES,AES");
			System.out.println("2. Hash algoritms: MD5, Sha-1 & SHA-2");
			System.out.println("3. Asym encryption: RSA-OAEP, RSA-PSS");
			System.out.println("0. EXIT.");
			opt = stdin.nextInt();

			switch(opt){

				
				case 1: //algo = "DES";
						String keyBC, plt, keyA2, pltA2;
						keyA2 = "8000000000000000000000000000000000000000000000000000000000000000";
						pltA2 = "0000000000000000000000000000000000000000000000000000000000000000";
						keyBC = "8000000000000000";
						plt = "0000000000000000";

						System.out.println("\n"); 
						System.out.println("             String                     key                          DES                         AES              AES256\n");
						System.out.println("Vector1     "+plt+"     "+keyBC+"           "+getDES(plt,keyBC)+"       "+getAES(plt,keyBC)+"          "+getAES256(pltA2,keyA2));

				break;
				case 2: String text = "";
						
						System.out.println("\n");
						System.out.println("             String                        MD5                       SHA-1                                  SHA-2 \n");
						System.out.println("Vector 1    "+text+"          "+getMd5(text)+"    "+getSHA1(text)+"     "+getSHA2(text));	
						System.out.println("                                 MD5 time: "+timeMd+"ms                    SHA-1 time: "+timeS1+"ms                       SHA-2 time: "+timeS2+"ms\n");
						
						text = "a";
						
						System.out.println("\n");
						System.out.println("             String                        MD5                       SHA-1                                  SHA-2 \n");
						System.out.println("Vector 1    "+text+"          "+getMd5(text)+"    "+getSHA1(text)+"     "+getSHA2(text));	
						System.out.println("                                 MD5 time: "+timeMd+"ms                    SHA-1 time: "+timeS1+"ms                       SHA-2 time: "+timeS2+"ms\n");

				break;
				case 3: //algo = "END";
						String keyAs = "9195E9854FA04A1433D4E22048951426A0ACFC6FE446730579D742CAEA5FDF6590FAEC7F71F3EBF0C6408564987D07E19EC07BC0F601B5E6ADB28D9AA6148FCC51CFF393178983790CC616C0EF34AB50DC8444F44E24117B46A47FA3630BF7E696865BFC245F7C3A314CD48C583D7B2223AF06881158557E37B3CC370AE6C8D5";
								

				break;
				default: break;
			}
			System.out.println(algo);
		}while(opt != 0);
		
	}
}