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
import java.util.Collections;
import java.util.InputMismatchException;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatClient extends ChatApplication implements Runnable {

	/* Network operation variables */
  private static Socket clientSocket = null;  // The client socket
  private static InputStream inStream;
  private static DataInputStream  inDataStream  =  null;
  private static OutputStream outStream;
  private static DataOutputStream outDataStream = null;  // The output stream
  private static BufferedReader inputLine = null;
  private static boolean closed = false;

	/* Cryptographic keys */
	private static PublicKey pub;
	private static PrivateKey priv;
	private static byte[] DH_sess;
	private static Key AES_key, MAC_key;

	/* Cryptographic primitives */
	private static Cipher cipher;
	private static Signature sig;
	private static SecureRandom srand;
	private static MessageDigest sha;
	private static Mac mac;
	//private static SecretKeyFactory kdf;

  private static byte[] clientECDH( DataInputStream inStream,
                                  DataOutputStream outStream)
                                  throws Exception {
  // Generate ECDH keypair
  KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
  kpg.initialize(256);
  KeyPair kp = kpg.generateKeyPair();
  pub = kp.getPublic();
  priv = kp.getPrivate();
  byte[] clientPubKey = kp.getPublic().getEncoded();

  /* Encode to base64 */
  byte[] B64PKey = Base64.getEncoder().encode(clientPubKey);
  outStream.writeUTF(new String(B64PKey, "UTF-8"));

  /* Wait for client reply. */
  byte[] serverPubKey = Base64.getDecoder().decode(inStream.readUTF().getBytes());

  // Perform key agreement
  KeyFactory kf = KeyFactory.getInstance("EC");
  X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(serverPubKey);
  PublicKey serverPublicKey = kf.generatePublic(pkSpec);
  KeyAgreement ka = KeyAgreement.getInstance("ECDH");
  ka.init(kp.getPrivate());
  ka.doPhase(serverPublicKey, true);

  // Derive a key from the shared secret and both public keys
  MessageDigest hash = MessageDigest.getInstance("SHA-256");
  hash.update(ka.generateSecret());

  // Deterministic ordering
  List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(clientPubKey), ByteBuffer.wrap(serverPubKey));
  Collections.sort(keys);
  hash.update(keys.get(0));
  hash.update(keys.get(1));

  return hash.digest();
}

	/* Client half of the auth component. Assumes presence of a shared,
	 * pre-negotiated DH session key, and derived AES key. In the same
	 * spirit as the OTR protocol, MITM and replay attacks (such as those
	 * against the original PKI Needham-Schroeder protocol) are obviated by
	 * sending everything over an ECDH-pre-negotiated encrypted channel. */
	static boolean authOTRClient(	DataInputStream inStream,
																DataOutputStream outStream)
																throws Exception
	{
			byte[] nonceB = new byte[256];
			srand.nextBytes(nonceB);
			
			System.out.println("[+] starting signature");

			/* compute signature of authentication message */
			sig.initSign(priv);
			sig.update(pub.getEncoded());
			sig.update(nonceB);
			byte[] sigB = sig.sign();
			
			System.out.println(AES_key.toString());

			/* AES encrypt {pub_B, nonce_B, sig_B(pub_B, nonce_B)} */
			cipher.init(Cipher.ENCRYPT_MODE, AES_key);
			cipher.update(pub.getEncoded());
			cipher.update(nonceB);
			cipher.update(sigB);
			
			byte[] concat = new byte[pub.getEncoded().length + nonceB.length + sigB.length];
    System.arraycopy(pub.getEncoded(), 0, concat, 0, pub.getEncoded().length);
    System.arraycopy(nonceB, 0, concat, pub.getEncoded().length, nonceB.length);
    System.arraycopy(sigB, 0, concat, pub.getEncoded().length + nonceB.length, sigB.length);
    
    System.out.println("AES_key: " + AES_key.toString());
    System.out.println(concat[0]);
    
    byte[] authMessageAES = symmEncrypt(cipher, srand, AES_key, concat);
			
			byte[] authMB64 = Base64.getEncoder().encode(authMessageAES);

			outStream.writeUTF(new String(authMB64, "UTF-8"));
			
			System.out.println("[+] sent authentication message");
			/* Wait for server reply. */
			
			byte[] authResponseAES = Base64.getDecoder().decode(inStream.readUTF().getBytes());
			
			System.out.println("[+] got authentication response");

			byte[] iv = new byte[16];

			cipher.init(Cipher.DECRYPT_MODE, AES_key);
			byte[] authResponse = cipher.doFinal(authResponseAES);

			byte[] serverPub =   Arrays.copyOfRange(authResponse, 0, 48);
			byte[] serverNonce = Arrays.copyOfRange(authResponse, 48, 304);
			byte[] serverSig =   Arrays.copyOfRange(authResponse, 304, 418);

			PublicKey sPK = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(serverPub));

			sig.initVerify(sPK);
			sig.update(serverPub);
			sig.update(serverNonce);
			if(sig.verify(serverSig) == false){
				return false;
			}

			return true;
	}

	private static boolean requestSession(DataInputStream inStream,
																				DataOutputStream outStream)
																				throws IOException
	{
		/* Because both sides only accept preferences matching their own, attacks
		 * which downgrade an in-transit open message (e.g. from c:true to c:false)
		 * would not lead to loss of security, as at least one side would have to
		 * have not wanted that aspect anyway.
		 * The most a MITM attacker can do is deny new communications channels by
		 * changing the client's open messages to never match the server's
		 * preferences. */
		String response;
		String message = "open c:" + useConf + " i:" + useInteg + " a:" + useAuth;

		outStream.writeUTF(message);
		response = inStream.readUTF();

		if(response.equals("goahead"))
		{
			return true;
		}
		else
		{
			System.out.println("\n[/] Session request rejected: server reported" +
				" mismatching preferences:\n\t"+response);
			return false;
		}
	}

  public static void startClient()
																/*throws Exception*/{

    int portNumber = 23513;
    // Open a socket and streams
    try {
			if(remoteHost == null){
				System.out.println("[/] ERROR: No remote host provided");
				return;
			}
			clientSocket = new Socket(remoteHost,portNumber);

			/* SESSION OPENING */


					String message = "";


					/* Attempt to open session with server, supplying preferences. */
					DataInputStream inOpenStream  = new DataInputStream(clientSocket.getInputStream());
					DataOutputStream outOpenStream = new DataOutputStream(clientSocket.getOutputStream());

					System.out.print("[+] Requesting session with server...");

					if(requestSession(inOpenStream, outOpenStream) == false)
					{
						return;
					}
					System.out.println("OK.");

          inStream = clientSocket.getInputStream ();
					inDataStream = new DataInputStream ( inStream );
					outStream = clientSocket.getOutputStream ();
					outDataStream = new DataOutputStream (outStream);

		      /* SESSION KEY ESTABLISHMENT */

		      try
		      {
		        DH_sess = clientECDH(inDataStream, outDataStream);
		        System.out.println(DH_sess.toString());
		      } catch(Exception e){
		        System.out.println("[/] exception while doing ECDH exchange.");
		        System.out.println(e);
		        return;
		      }
		      
		      try 
		      {
  					AES_key = new SecretKeySpec(DH_sess, 0, 32, "AES");
  					MAC_key = new SecretKeySpec(DH_sess, 0, 32, "AES");
					}
					catch(Exception e)
					{
			 			System.out.println("[!] ERROR: exception while generating subkeys");
        		System.out.println(e);
        		return;
					}

    			System.out.println("[+] Connection opened on "+remoteHost+":"+portNumber);

          inputLine = new BufferedReader(new InputStreamReader(System.in));

    			/* AUTHENTICATION */

			if(useAuth)
			{
				try
			 	{
					if(authOTRClient(inDataStream, outDataStream) == false)
					{
						System.out.println("[/] application could not authenticate");
						return;
					}
				}
				catch (Exception e){
					System.out.println("[!] exception while authenticating");
					System.out.println(e);
					return;
				}
			}
    } catch (UnknownHostException e) {
      System.err.println("Don't know about host " + remoteHost);
    } catch (IOException e) {
      System.err.println("Couldn't get I/O for the connection to the host");
    }
  }

  // Create a thread to read from the server
  public void run() {

    /* MAIN RECEIVE LOOP */
    String responseLine;
    byte[] plainResponse, macResponse, aesResponse, B64Response;
    try
    {
      while ((B64Response = inDataStream.readUTF().getBytes()) != null)
      {
				/* base64 decode */
      	aesResponse = Base64.getDecoder().decode(B64Response);

      	/* Symmetrically decrypt if specified */
      	if(useAuth)
      	{
      		macResponse = symmDecrypt(cipher, AES_key, aesResponse);
      	}
      	else
      	{
      		macResponse = aesResponse;
      	}

      	if(macResponse == null){
      		continue;
      	}

      	/* Check integrity if specified, returning warning if MAC check fails */
      	if(useInteg)
      	{
      		plainResponse = checkMAC(mac, MAC_key, macResponse);
      	}
      	else
      	{
      		plainResponse = macResponse;
      	}

      	if(plainResponse == null){
      		continue;
      	}

      	/* display message */
      	responseLine = new String(plainResponse, "UTF-8");
      	System.out.print("[<] ");
      	System.out.println(responseLine);

      	/* close if message was "bye" */
        if (responseLine.indexOf(".bye") != -1)
        {
          break;
        }
      }
      closed = true;
    }
    catch (IOException e)
    {
      System.err.println("[!] IOException:  " + e);
    }
  }

  public static void close() throws IOException {
		if (clientSocket != null) clientSocket.close();
    if (inDataStream != null)  inDataStream.close();
    if (outDataStream != null)  outDataStream.close();
  }

  public static void main(String[] args) throws IOException {
		/* PRIMITIVE INITIALISATION */

				try
				{
					sha = MessageDigest.getInstance("SHA-256");
					cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					sig = Signature.getInstance("SHA256withECDSA");
	        //srand = SecureRandom.getInstance("NativePRNG");
	  			srand = new SecureRandom();
	  			mac = Mac.getInstance("HmacSHA256");
  				//kdf = SecretKeyFactory.getInstance("AES");
				}
				catch(NoSuchAlgorithmException | NoSuchPaddingException e)
				{
					System.out.println("[!] ERROR: Could not obtain cryptographic function");
					System.out.println(e);
					return;
				}

				/* Get feature preferences, and username, if specified. */
				parseArgs(args);

		/* LOCAL AUTHENTICATION */

				/* If specified, get password, compute its local hash, and immediately
				 * blank the plaintext password array. */
				if(promptPass)
				{
					localHash = getLocalHash(sha);
				}

				/* Check the local password hash (null if not given) against the
				 * application's read-protected hash file. */
				if(checkLocalHash(localHash) == false){
					System.out.println("[/] Credentials could not be matched.");
					return;
				}
		  	else {
					System.out.println("[+] Locally authenticated.");
				}

    startClient();
    if (clientSocket != null && outDataStream != null && inDataStream != null)
    {
      try
      {
        /* MAIN SEND LOOP */

        // Create a thread to read from the server.
        new Thread(new ChatClient()).start();
        byte[] plainMessage, macMessage, aesMessage, B64Message;

        while (!closed)
        {
        	plainMessage = inputLine.readLine().trim().getBytes();

        	if(plainMessage == null){
      			continue;
      		}

        	/* Add integrity check if specified */
        	if(useInteg)
        	{
        		macMessage = addMAC(mac, MAC_key, plainMessage);
        	}
        	else
        	{
        		macMessage = plainMessage;
        	}

        	if(macMessage == null){
      			continue;
      		}

        	/* Symmetrically encrypt if specified */
        	if(useConf)
        	{
        		aesMessage = symmEncrypt(cipher, srand, AES_key, macMessage);
        		Arrays.fill(plainMessage, (byte) 0);
        		Arrays.fill(macMessage, (byte) 0);
        	}
        	else
        	{
        		aesMessage = macMessage;
        	}

        	if(aesMessage == null){
      			continue;
      		}

        	/* Encode to base64 */
        	B64Message = Base64.getEncoder().encode(aesMessage);

        	/* Send */
          outDataStream.writeUTF(new String(B64Message, "UTF-8"));
          outDataStream.flush();
        }
        /* END MAIN SEND LOOP */

        close();
      }
      catch (IOException e)
      {
        System.out.println("[!] ERROR: IOException while sending message");
        System.err.println(e);
      }
    }
  }
}
