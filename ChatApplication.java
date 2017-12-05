import java.io.*;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.InputMismatchException;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ChatApplication 
{
	static String pwFile = "./pw/passwd";
	static boolean useConf, useInteg, useAuth;
	static boolean promptPass = false;
	static String uname, remoteHost;
	static byte[] localHash;
	
	/* LOCAL AUTHENTICATION AND ACCESS FUNCTIONS */
	
	static void parseArgs(String[] args)
	{
		/* Loop through argument strings, looking for option flags */
		if(args.length == 0){
			return;
		}
		for(int i = 0; i < args.length; i++)
		{
			if(args[i].equals("-c"))
			{
				useConf = true;
			}
			else if(args[i].equals("-i"))
			{
				useInteg = true;
			}
			else if(args[i].equals("-a"))
			{
				useAuth = true;
			}
			else if(args[i].equals("-p"))
			{
				promptPass = true;
				continue;
			}
			else if(args[i].equals("-u"))
			{
				i += 1;
				if(i >= args.length)
				{
					System.out.println("[/] ERROR: No username provided");
					throw new InputMismatchException();
				}
				uname = args[i];
			}
			else if(args[i].equals("-h"))
			{
				i += 1;
				if(i >= args.length)
				{
					System.out.println("[/] ERROR: No remote host provided");
					throw new InputMismatchException();
				}
				remoteHost = args[i];
			}
			else {
				System.out.println("[/] ERROR: Unrecognised option: " + args[i]);
				throw new InputMismatchException();
			}
		}
	}
	
	static byte[] getLocalHash(MessageDigest hash)
	{
		System.out.print("Password: ");
		/* Read plaintext password without echoing */
		char[] passwd = System.console().readPassword();
		
		/* Convert char[] array to byte[] array for digest function */
		CharBuffer charBuffer = CharBuffer.wrap(passwd);
		ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
			byteBuffer.position(),
			byteBuffer.limit());

		/* Feed passwd bytes into digest function */
		hash.update(bytes);

		/* Blank plaintext char and byte arrays */
		Arrays.fill(charBuffer.array(), '\u0000');
		Arrays.fill(byteBuffer.array(), (byte) 0);

		return hash.digest();
			
	}
	
	static byte[] stringToHexBytes(String str)
	{
		int len = str.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) 
    {
        data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4)
                             + Character.digit(str.charAt(i+1), 16));
    }
    return data;
	}
	
	static boolean checkLocalHash(byte[] localHash) throws IOException
	{
		System.out.println("[+] checking hash file at "+pwFile);
		
		Path pwPath = Paths.get(pwFile);
		BufferedReader pwReader;
		String[] entryPair;
	
		/* Try opening the path supposedly pointing to the hash file */
		if(	(Files.isRegularFile(pwPath) == false) || 
				(Files.isReadable(pwPath) == false))
		{
			System.out.println("[!] ERROR: path to hash file not valid");
			return false;
		}
		try {
			pwReader = Files.newBufferedReader(pwPath);
		}
		catch (Exception e){
			System.out.println ("[!] ERROR: could not open hash file");
			System.out.println(e);
			return false;
		}
		
		/* Find entry for uname and compare hashes */
		String entry = pwReader.readLine();
		while (entry != null)
		{
			entryPair = entry.split(":");	
			if(entryPair[0].equals(uname))
			{
				byte[] hashBytes = stringToHexBytes(entryPair[1]);
				if(Arrays.equals(hashBytes, localHash))
				{
					pwReader.close();
					return true;
				}
			}
			entry = pwReader.readLine();
		}
		pwReader.close();
		return false;
	}
	
	/* SYMMETRIC CRYPTOGRAPHY FUNCTIONS */
	
	static byte[] symmEncrypt(Cipher cipher, SecureRandom srand, Key symm_key, byte[] plainMessage) 
	{
		assert(symm_key != null);
		
		try 
		{
			byte[] iv = new byte[16];
			srand.nextBytes(iv);
			
			cipher.init(Cipher.ENCRYPT_MODE, symm_key, new IvParameterSpec(iv));
			
			byte[] symmMessage = cipher.doFinal(plainMessage);
			byte[] symmMessageWithIV = new byte[symmMessage.length + iv.length];
			System.arraycopy(iv, 0, symmMessageWithIV, 0, iv.length);
			System.arraycopy(symmMessage, 0, symmMessageWithIV, iv.length, symmMessage.length);
			
			return symmMessageWithIV;
		}
		catch (Exception e){
			System.err.println("[!] ERROR: error while encrypting message");
			System.err.println(e);
			return null;
		}
	}
	
	static byte[] symmDecrypt(Cipher cipher, Key symm_key, byte[] symmMessageWithIV) 
	{
		assert(symm_key != null);
		
		try 
		{
			byte[] iv = new byte[16];
			byte[] symmMessage = new byte[symmMessageWithIV.length - iv.length];
			
			System.arraycopy(symmMessageWithIV, 0, iv, 0, iv.length);
			System.arraycopy(symmMessageWithIV, iv.length, symmMessage, 0, symmMessageWithIV.length - iv.length);
			
			cipher.init(Cipher.DECRYPT_MODE, symm_key, new IvParameterSpec(iv));
			return cipher.doFinal(symmMessage);
		}
		catch (Exception e){
			System.err.println("[!] ERROR: error while decrypting message");
			System.err.println(e);
			return null;
		}
	}
	
	/* MESSAGE AUTHENTICATION FUNCTIONS */
	
	static byte[] addMAC(Mac mac, Key mac_key, byte[] plainMessage)
	{
		assert(mac_key != null);
		try 
		{
			mac.init(mac_key);
			mac.update(plainMessage);
			byte[] hMac = mac.doFinal();
	
			/* Append HMAC to message */
			byte[] macMessage = new byte[plainMessage.length + hMac.length];
	
			System.arraycopy(plainMessage, 0, macMessage, 0, plainMessage.length);
			System.arraycopy(hMac, 0, macMessage, plainMessage.length, macMessage.length);
	
			return macMessage;
		}
		catch (InvalidKeyException e){
			System.err.println("[!] ERROR: error while calculating outgoing MAC");
			System.err.println(e);
			return null;
		}
	}
	
	static byte[] checkMAC(Mac mac, Key mac_key, byte[] macMessage)
	{
		String macMismatchWarning = "[x] WARNING: MAC mismatch; cannot trust integrity of following message:\n\t";
	
		assert(mac_key != null);
		
		try {
			/* separate HMAC from message */
			mac.init(mac_key);
			byte[] hMac = new byte[mac.getMacLength()];
			byte[] plainMessage = new byte[macMessage.length - mac.getMacLength()];
		
			System.arraycopy(macMessage, 0, plainMessage, 0, macMessage.length - mac.getMacLength());
			System.arraycopy(macMessage, macMessage.length - mac.getMacLength(), hMac, 0, mac.getMacLength());
		
			mac.update(plainMessage);
			if(Arrays.equals(hMac, mac.doFinal()))
			{
				return plainMessage;
			}
			else 
			{
				byte[] warning = macMismatchWarning.getBytes();
				byte[] warningMessage = new byte[plainMessage.length + warning.length];
			
				System.arraycopy(warning, 0, warningMessage, 0, warning.length);
				System.arraycopy(plainMessage, 0, warningMessage, warning.length, plainMessage.length);

				return warningMessage;
			}
		}
		catch (InvalidKeyException e){
			System.err.println("[!] ERROR: error while checking incoming MAC");
			System.err.println(e);
			return null;
		}
	}
}
