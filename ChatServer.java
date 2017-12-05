import java.io.*;
import java.net.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.nio.CharBuffer;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.InputMismatchException;
import java.util.List;


public class ChatServer extends ChatApplication implements Runnable
{
  /* Network operation variables */
  private static Socket       socket = null;
  private static ServerSocket server = null;
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
	//private static KeyGenerator kdf;

  private static byte[] serverECDH( DataInputStream inStream,
									DataOutputStream outStream)
									throws Exception {

    // Generate ECDH keypair
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();
    pub = kp.getPublic();
    priv = kp.getPrivate();
    byte[] serverPubKey = kp.getPublic().getEncoded();

    /* Encode to base64 */
	  byte[] B64PKey = Base64.getEncoder().encode(serverPubKey);
    outStream.writeUTF(new String(B64PKey, "UTF-8"));

    /* Wait for client reply. */
    byte[] clientPubKey = Base64.getDecoder().decode(inStream.readUTF().getBytes());

    // Perform key agreement
    KeyFactory kf = KeyFactory.getInstance("EC");
    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPubKey);
    PublicKey clientPublicKey = kf.generatePublic(pkSpec);
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(kp.getPrivate());
    ka.doPhase(clientPublicKey, true);

    // Derive a master key from the shared secret and both public keys
    MessageDigest hash = MessageDigest.getInstance("SHA-256");
    hash.update(ka.generateSecret());

    // Deterministic ordering
    List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(serverPubKey), ByteBuffer.wrap(clientPubKey));
    Collections.sort(keys);
    hash.update(keys.get(0));
    hash.update(keys.get(1));

    return hash.digest();
  }

  static boolean checkOpenRequest(String message){
    String[] split = message.split(" ");
    if(
    (split.length != 4) ||
    !(split[0].equals("open")) ||
    !(split[1].split(":")[1].equals(String.valueOf(useConf))) ||
    !(split[2].split(":")[1].equals(String.valueOf(useInteg))) ||
    !(split[3].split(":")[1].equals(String.valueOf(useAuth)))
    )
    {
      return false;
    }
    return true;
  }

  /* Server half of the auth component. Assumes presence of a shared,
  * pre-negotiated DH session key, and derived AES and MAC keys. In the same
  * spirit as the OTR protocol, MITM and replay attacks (such as those
  * against the original PKI Needham-Schroeder protocol) are obviated by
  * sending everything over an ECDH-pre-negotiated encrypted channel. */
  private static boolean authOTRServer(	SecureRandom srand,
  Signature sig,
  Cipher cipher,
  DataInputStream inStream,
  DataOutputStream outStream)
  throws Exception
  {
    byte[] nonceA = new byte[256];
    srand.nextBytes(nonceA);

		String authMessageString = inStream.readUTF();
    byte[] authMessageAES = Base64.getDecoder().decode(authMessageString);
    

    
		System.out.println("[+] got authentication message");

    byte[] authMessage = symmDecrypt(cipher, AES_key, authMessageAES);
    
    System.out.println("AES_key: " + AES_key.toString());
    System.out.println(authMessage[0]);

    byte[] clientPub =   Arrays.copyOfRange(authMessage, 0, 48);
    byte[] clientNonce = Arrays.copyOfRange(authMessage, 48, 304);
    byte[] clientSig =   Arrays.copyOfRange(authMessage, 304, 418);

		System.out.println("[+] got things");

    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPub); 
    KeyFactory keyfactory = KeyFactory.getInstance("RSA");
    PublicKey encodedPK = keyfactory.generatePublic(keySpec);

    sig.initVerify(encodedPK);
    sig.update(clientPub);
    sig.update(clientNonce);
    if(sig.verify(clientSig) == false){
      return false;
    }

    /* We now believe the sender is in control of clientPriv. */

    sig.initSign(priv);
    sig.update(pub.getEncoded());
    sig.update(nonceA);
    byte[] sigA = sig.sign();

    /* AES encrypt {pub_A, nonce_A, sig_A(pub_A, nonce_A)} */
    byte[] concat = new byte[pub.getEncoded().length + nonceA.length + sigA.length];
    System.arraycopy(pub.getEncoded(), 0, concat, 0, pub.getEncoded().length);
    System.arraycopy(nonceA, 0, concat, pub.getEncoded().length, nonceA.length);
    System.arraycopy(sigA, 0, concat, pub.getEncoded().length + nonceA.length, sigA.length);
    
    byte[] authResponseAES = symmEncrypt(cipher, srand, AES_key, concat);
    byte[] authRB64 = Base64.getEncoder().encode(authResponseAES);
    outStream.writeUTF(new String(authRB64, "UTF-8"));
    
    System.out.println("[+] sent authentication response");

    /* Everything is peachy on our end, at least */

    return true;
  }

  public static void startServer(	SecureRandom srand,
																Signature sig,
																Cipher cipher)
																/*throws Exception*/{
    int portNumber = 23513;
    // Open a socket and streams
    try {
      String message="";
      server = new ServerSocket(portNumber);
      System.out.println("[+] Server started: " + server);
      inputLine = new BufferedReader(new InputStreamReader(System.in));
      System.out.print("[+] Waiting for a client... ");
      socket = server.accept();
      System.out.println("Client accepted: " + socket);
      inStream = socket.getInputStream ();
      inDataStream = new DataInputStream ( inStream );
      outStream = socket.getOutputStream();
      outDataStream = new DataOutputStream (outStream);

      message = inDataStream.readUTF();

      if(checkOpenRequest(message)){
        outDataStream.writeUTF("goahead");
      }
      else {
        outDataStream.writeUTF("mismatch c:"+useConf + " i:"+useInteg + " a:"+useAuth);
      }
      outDataStream.flush();

      inStream = socket.getInputStream ();
      inDataStream = new DataInputStream ( inStream );
      outStream = socket.getOutputStream();
      outDataStream = new DataOutputStream (outStream);

      /* SESSION KEY ESTABLISHMENT */

      try{
        DH_sess = serverECDH(inDataStream, outDataStream);
        System.out.println(DH_sess.toString());
      } catch(Exception e){
        System.out.println("[!] ERROR: exception while doing ECDH exchange");
        System.out.println(e);
        return;
      }
      System.out.println("[+] ECDH exchange completed.");
      
      /* 256-bit sub-key establishment for AES and HMAC */
      try {
      	System.out.println(Arrays.toString(DH_sess));
      	System.out.println(DH_sess.length);
      	AES_key = new SecretKeySpec(DH_sess, 0, 32, "AES");
      	MAC_key = new SecretKeySpec(DH_sess, 0, 32, "AES");
			}
			catch(Exception e){
			  System.out.println("[!] ERROR: exception while generating subkeys");
        System.out.println(e);
        return;
			}
			
      /* AUTHENTICATION */

      if(useAuth)
      {
        try
        {
          if(authOTRServer(srand, sig, cipher, inDataStream, outDataStream) == false)
          {
            System.out.println("[/] application could not authenticate");
            return;
          }
        }
        catch (Exception e){
          System.out.println("[/] exception while authenticating");
          System.out.println(e);
          return;
        }
      }

      /* MAIN SEND/RECIEVE LOOP */
      System.out.println("[+] Client connected with matching preferences.");

    } catch (IOException e) {
      System.err.println("[/] Couldn't get I/O for the connection");
      System.out.println(e);
    }
  }

  // Create a thread to read from the client.
  public void run(){
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

		    	/* Check integrity if specified, returning warning if MAC check fails */
		    	if(useInteg)
		    	{
		    		plainResponse = checkMAC(mac, MAC_key, macResponse);
		    	}
		    	else
		    	{
		    		plainResponse = macResponse;
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
		  catch(IOException ie)
		  {
		    System.out.println("[!] ERROR: Acceptance Error: " + ie);
		  }
		}
    public static void close() throws IOException {
      if (socket != null)    socket.close();
      if (inDataStream != null)  inDataStream.close();
      if (outDataStream != null)  outDataStream.close();
    }

    public static void main(String args[]) throws IOException {
      /* PRIMITIVE INITIALISATION */


      try
      {
        sha = MessageDigest.getInstance("SHA-256");
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        sig = Signature.getInstance("SHA256withRSA");
        //srand = SecureRandom.getInstance("NativePRNG");
  			srand = new SecureRandom();
  			mac = Mac.getInstance("HmacSHA256");
  			//kdf = KeyGenerator.getInstance("AES");

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

      /* SESSION OPENING */
      startServer(srand, sig, cipher);

      try {
        new Thread(new ChatServer()).start();
        byte[] plainMessage, macMessage, aesMessage, B64Message;
        while (!closed)
        {
          plainMessage = inputLine.readLine().trim().getBytes();

        	/* Add integrity check if specified */
        	if(useInteg)
        	{
        		macMessage = addMAC(mac, MAC_key, plainMessage);
        	}
        	else
        	{
        		macMessage = plainMessage;
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

        	/* Encode to base64 */
        	B64Message = Base64.getEncoder().encode(aesMessage);

        	/* Send */
          outDataStream.writeUTF(new String(B64Message, "UTF-8"));
          outDataStream.flush();
        }
        close();
      }
      catch (IOException e)
      {
        System.err.println("IOException:  " + e);
      }
    }
  }
