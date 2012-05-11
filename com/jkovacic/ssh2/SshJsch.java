/*
Copyright 2012, Jernej Kovacic

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/ 

package com.jkovacic.ssh2;

import java.util.*;
import java.io.*;

import com.jkovacic.cli.*;
import com.jkovacic.cryptoutil.*;

import com.jcraft.jsch.*;

/**
 * Implementation of Ssh2 using an open source (BSD style license)
 * library JSch. More info: http://www.jcraft.com/jsch/
 *
 * This implementation was developed on version 0.1.46
 * 
 * Note, the JSch project does not provide any documentation.
 * There is a 3rd party JSch documentation project at: http://epaul.github.com/jsch-documentation/
 * or a direct link to API: http://epaul.github.com/jsch-documentation/javadoc/
 * 
 * @author Jernej Kovacic
*/
public final class SshJsch extends Ssh2 
{
	// Available algorithms, discovered by scrutinizing of JSch source code:
	private static final String[] AVAILABLE_KEX_ALGS =
		{ 
		"diffie-hellman-group-exchange-sha1", 
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1"
        };
	
	private static final String[] AVAILABLE_HMAC_ALGS =
		{
		"hmac-md5", 
		"hmac-sha1", 
		"hmac-md5-96", 
		"hmac-sha1-96"
		};
	
	private static final String[] AVAILABLE_CIPHER_ALGS =
		{
		"blowfish-cbc",
		"3des-cbc",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
		"3des-ctr",
		"arcfour",
		"arcfour128",
		"arcfour256"
		};
		
	private static final String[] AVAILABLE_PK_ALGS =
		{
		"ssh-dss",
		"ssh-rsa"
		};
	
	private static final String[] AVAILABLE_COMP_ALGS =
		{
		"zlib", 
		"zlib@openssh.com",
		"none"
		};
	
	// JSch connection context
	private JSch jschcontext = null;
	// SSH session context
	private Session sshconn = null;
	
	
	/*
	 * Constructor 
	 * 
	 * @param host - a class with SSH server data
	 * @param user - user's data needed for authentication
	 * @param algorithms - selected encryption algorithms
	 */
	SshJsch(HostId host, UserCredentials user, EncryptionAlgorithms algorithms)
	{
		super(host, user, algorithms);
		
		// Supported algorithms, discovered by scrutinizing of JSch source code:
		
		// Key exchange algorithms supported by the library:
		availableKexAlgs = AVAILABLE_KEX_ALGS;
		
		// Hmac algorithms supported by the library
		availableHmacAlgs = AVAILABLE_HMAC_ALGS;
		
		// Cipher algorithms supported by the library
		availableCipherAlgs = AVAILABLE_CIPHER_ALGS;
		
		// Public key algorithms supported by the library
		availablePublickeyAlgs = AVAILABLE_PK_ALGS;
		
		// Compression algorithms supported by the library
		availableCompAlgs = AVAILABLE_COMP_ALGS;
		
		
		// instantiate JSch
		this.jschcontext = new JSch();
	}
	
	/*
	 * A utility function that converts an array of strings to a single
	 * string with comma separated members of the array
	 * 
	 * @param list - array of strings
	 * 
	 * @return string comma separated elements of list
	 */
	private String listToLine(String[] list)
	{
		StringBuffer buf = new StringBuffer();
		if ( null != list )
		{ 
			for ( String alg : list )
			{
				// append each member to the string buffer
				buf.append(alg);
				// followed by a comma
				buf.append(',');
			}
			
			// and remove the last comma at the end
			if ( buf.length() > 0 )
			{
				buf.deleteCharAt(buf.length()-1);
			}
		}
		
		return buf.toString();
	}
	
	/*
	 * Adds internal (i.e. the library based) instance of IdentityFile into the IdentityRepository.
	 * This method does not require implementation of a SSH signature agent. Instead,
	 * a class with such a functionality is instantiated by the library.
	 * On the other hand, only RSA and 1024-bit DSA digital signature scheme is possible 
	 * by this method.
	 * 
	 * @throws SshException if anything fails
	 */
	// Currently this functionality is not used, resulting in a compiler warning.
	// However, it may be useful (again) some time in the future, so for now
	// it will be commented out to suppress the warning.
	/*
	private void addInternalIdentity() throws SshException
	{
		// Public key authentication. Key material will be parsed from user settings,
		// then an instance of Identity will be created and passed to the Jsch context.
		 
		UserCredentialsPrivateKey pkinst = (UserCredentialsPrivateKey) user;
		// Parse the specified DER encoded private key information
		DerDecoderPrivateKey decoder = new DerDecoderPrivateKey(pkinst.getMethod().toCU(), pkinst.getSecret());
		decoder.parse();
		if ( false==decoder.ready() )
		{
			throw new SshException("Could not prepare a keypair");
		}
		
		// JSch's Identity factory requires the keys' parameters as
		// SSH formatted vectors in the correct order (depending on key type)
		SshFormatter cnv = new SshFormatter();
		byte[] empty = new byte[0];
		String identity = user.getUsername() + "@" + destination.hostname + ":" + destination.port;
		
		// regardless of the key type, the first vector is a string with algorithm's name
		cnv.add(pkinst.getMethod().getName());
		
		// The exact order of key parameter vectors was discovered by scrutinizing of JSch source code
		switch ( pkinst.getMethod() )
		{
		case RSA:
			cnv.add(decoder.get('n'));
			cnv.add(decoder.get('e')); 
			cnv.add(decoder.get('d'));
			cnv.add(empty);
			cnv.add(empty);
			cnv.add(empty);
			cnv.add(identity);
			break;
			
		case DSA:
			cnv.add(decoder.get('p'));
			cnv.add(decoder.get('q'));
			cnv.add(decoder.get('g'));
			cnv.add(decoder.get('y'));
			cnv.add(decoder.get('x'));
			cnv.add(identity);
			break;
			
		default:
			throw new SshException("Unsupported asymmetric encryption algorithm");
		}
		
		// The key material structure is ready to instantiate an 
		// instance of Identity and pass it to the JSch context
		try
		{
			jschcontext.addIdentity(identity, cnv.format(), null, null);
		}
		catch ( JSchException ex )
		{
			throw new SshException("Could not add an identity");
		}
	}
	*/
	
	/**
	 * Establishes a connection to the SSH server, performs host checking and also
	 * user authentication. When the connection is established, individual SSH channels
	 * may be opened (e.g. for remote execution by calling exec()). When not needed anymore, 
	 * the connection should be terminated by calling disconnect().
	 * 
	 * @throws SshException if something fails
	 */
	public void connect() throws SshException 
	{
		// JSch should have been instantiated by the constructor
		if ( null == jschcontext )
		{
			throw new SshException("JSch not instantiated");
		}

		// thoroughly check all settings
		shortlistAndCheckAlgorithms();
		checkUserSettings();
		checkDestHostSettings();
		
		// Settings look good, let's try to establish the connection
		try
		{
			// instantiate the internal class that will verify server's host keys
			jschcontext.setHostKeyRepository(new HostkeyChecker(destination.hostkeys));
					
			// A part of user authentication must be handled now.
			if ( UserCredentialsPassword.class == user.getClass() )
			{
				// nothing to do right now, this will be set when a Session is instantiated
			}
			else if ( UserCredentialsPrivateKey.class == user.getClass() )
			{
				/*
				 * Instantiate a class implementing Identity that actually performs digital
				 * signature procedures. At this moment, a class implementing SSH agent functionality
				 * is used. It is also possible to use the library's internal implementation of this
				 * interface which supports a limited number of encryption algorithms
				 * (RSA and 1024-bit DSA). If you still want to use it, just uncomment the
				 * line below, uncomment implementation of the function and comment out the rest of this function:
				 */
				
				// addInternalIdentity()
				
				UserCredentialsPrivateKey pkinst = (UserCredentialsPrivateKey) user;
				jschcontext.addIdentity(
						new AuthBlobSigner(pkinst.getMethod(), pkinst.getSecret()), 
						null);
			}
			else
			{
				throw new SshException("Unsupported authentication method");
			}
			
			// instantiate a session context, requiring information about username, destination and port
			sshconn = jschcontext.getSession(user.username, destination.hostname, destination.port);
			
			
			// Inform JSch about desired encryption algorithms
			String tmpStr;
			tmpStr = listToLine(cipherAlgs);
			sshconn.setConfig("cipher.c2s", tmpStr);
			sshconn.setConfig("cipher.s2c", tmpStr);
			tmpStr = listToLine(hmacAlgs);
			sshconn.setConfig("mac.c2s", tmpStr);
			sshconn.setConfig("mac.s2c", tmpStr);
			tmpStr = listToLine(kexAlgs);
			sshconn.setConfig("kex", tmpStr);
			tmpStr = listToLine(hostkeyAlgs);
			sshconn.setConfig("server_hostkey", tmpStr);
			tmpStr = listToLine(compAlgs);
			sshconn.setConfig("compression.c2s", tmpStr);
			sshconn.setConfig("compression.s2c", tmpStr);
			
			
			// if password authentication is selected, also assign the password
			if ( UserCredentialsPassword.class == user.getClass() )
			{
				sshconn.setPassword(user.getSecret() );
			}
			
			// All settings have been applied, let's try to actually connect and authenticate
			sshconn.connect();
			
			isConnected = sshconn.isConnected();
			
		}
		catch ( JSchException ejsch )
		{
			throw new SshException("Connection failed: '" + ejsch.getMessage() + "'");
		}
	}

	/**
	 * Terminate the SSH connection
	 * 
	 * @throws SshException if it fails
	 */
	public void disconnect() throws SshException 
	{
		sshconn.disconnect();
		isConnected = false;
	}

	/**
	 * Execute a command remotely over SSH 'exec'
	 * 
	 * Note: if a SSH server does not support returning exit codes, the library
	 * will return -1, so it is impossible to determine whether this was returned
	 * by the remote process or it is just a library's signal.
	 * 
	 * @param processor - a class that will process the command's outputs
	 * @param command - full command to execute, given as one line
	 * 
	 * @return an instance of CliOutput with results of the executed command
	 * 
	 * @throws CliException when execution fails for any reason
	 */
	public CliOutput exec(ICliProcessor processor, String command) throws SshException 
	{
		CliOutput retVal = null;
		
		// sanity check
		if ( null == command || 0 == command.length() )
		{
			throw new SshException("No command specified");
		}
		
		// is the connection established?
		if ( null == sshconn || false == isConnected )
		{
			throw new SshException("SSH connection not established");
		}
				
		try
		{
			// Prepare an exec channel
			ChannelExec channel = (ChannelExec) sshconn.openChannel("exec");
			// set the desired command
			channel.setCommand(command);
			
			// and try to execute it
			channel.connect();
			
			try
			{
				retVal = processor.process(channel.getOutputStream(), channel.getInputStream(), channel.getErrStream() );
			}
			catch ( CliException ex )
			{
				throw new SshException("Processing of output streams failed: " + ex.getMessage());
			}
			catch ( IOException ex )
			{
				throw new SshException("Could not access output streams");
			}
			
			// make sure the remote execution has completed (exec channel has closed)
			while ( false==channel.isClosed() )
			{
				try
				{
					Thread.sleep(100);
				}
				catch ( InterruptedException ex )
				{}
				
			}
			
			// and fetch the status (if the SSH server supports it):
			
			/*
			 * If the SSH server does not support exit code, it will return -1
			 * (also returned when channel type is not supposed to return getExitStatus etc.)
			 * Unfortunately, -1 is a legitimate return value, making it very difficult
			 * to guess, whether it was returned by the remote process or "just" the library.
			 */ 
			retVal.exitCode = channel.getExitStatus();
			
			// disconnect the exec channel (the session remains connected)
			channel.disconnect();
		}
		catch ( JSchException ex )
		{
			throw new SshException("Exec failed: '" + ex.getMessage() + "'");
		}
		
		return retVal;
	}

	/*
	 * Destructor.
	 * 
	 * It disconnects from a SSH server if the connection is still active
	 */
	protected void finalize() throws Throwable
	{
		try
		{
			disconnect();
		}
		finally
		{
			super.finalize();
		}
	}
	
	/**
	 * @return list of key exchange algorithms supported by the library
	 */
	public static String[] availableKexAlgorithms()
	{
		return AVAILABLE_KEX_ALGS;
	}
	
	/**
	 * @return list of symmetric cipher algorithms supported by the library
	 */
	public static String[] availableCipherAlgorithms()
	{
		return AVAILABLE_CIPHER_ALGS;
	}
	
	/**
	 * @return list of message integrity algorithms supported by the library
	 */
	public static String[] availableHmacAlgorithms()
	{
		return AVAILABLE_HMAC_ALGS;
	}
	
	/**
	 * @return list of asymmetric encryption algorithms supported by the library
	 */
	public static String[] availablePublicKeyAlgorithms()
	{
		return AVAILABLE_PK_ALGS;
	}
	
	/**
	 * @return list of compression algorithms supported by the library
	 */
	public static String[] availableCompressionAlgorithms()
	{
		return AVAILABLE_COMP_ALGS;
	}

	/*
	 * An internal class (not to be used outside of the main class) that
	 * implements JSch's HostKeyRepository with strict host key checking.
	 * 
	 * @author Jernej Kovacic
	 */
	private class HostkeyChecker implements HostKeyRepository
	{
		// A class that actually performs host verification
		private HostkeyVerifier hkverify = null;
		
		/*
		 * Constructor
		 *  
		 * @param hkeys - list of valid host public keys
		 */
		public HostkeyChecker(List<Hostkey> hkeys)
		{
			this.hkverify = new HostkeyVerifier(hkeys);
		}
		
		/*
		 * Check if the given public key is among valid ones
		 * 
		 * @param host - host name, ignored by this implementation
		 * @param key - public key blob to be checked
		 * 
		 * @return HostKeyRepository.OK if the key matches any valid key, HostKeyRepository.CHANGED otherwise
		 */
		public int check(String host, byte[] key)
		{
			// the whole verification process is actually implemented by HostkeyVerifier
			return ( true==hkverify.strictVerify(null, key) ?
					HostKeyRepository.OK : HostKeyRepository.CHANGED );
		}
		
		// The following functions are meaningless for our purposes but still
		// must be implemented as the interface requires so. 
		// Hence they are "implemented" as empty functions.
		public void add(HostKey hostkey, UserInfo ui)
		{		
			// Empty, no need to implement anything
		}
		
		public void remove(String host, String type)
		{
			// Empty, no need to implement anything
		}
		
		public void remove(String host, String type, byte[] key)
		{
			// Empty, no need to implement anything
		}
		
		public String getKnownHostsRepositoryID()
		{
			// this is used for JSch's book keeping purposes and can be assigned just any string
			return "application's repo";
		}
		
		// two more meaningless functions (can return anything of the valid type), 
		// required by the interface
		public HostKey[] getHostKey()
		{
			// no need to implement anything
			return null;
		}
		
		public HostKey[] getHostKey(String host, String type)
		{
			// no need to implement anything
			return null;
		}
	}
	
	/*
	 * An internal class (not to be used outside of the main class) that
	 * implements JSch's interface Identity. It performs digital signature
	 * and implements a SSH agent. It may be useful to support additional 
	 * signature algorithms, not supported by the JSch library (e.g. ECDSA),
	 * to use other cryptographic providers etc. 
	 * 
	 * @author Jernej Kovacic
	 */
	private class AuthBlobSigner implements Identity
	{
		// Public key blob, often required by the library routines
		private byte[] pubkey = null;
		
		// Asymmetric algorithm
		private PKAlgs method = null;
		
		// Key pair
		private KeyCreator kc = null; 
		
		/*
		 * Constructor, initializes the class
		 * 
		 * @param method - asymmetric encryption algorithm
		 * @param key - DER encoded key material
		 */
		public AuthBlobSigner(PKAlgs method, byte[] key)
		{
			this.method = method;
			getKeyMaterial(key);
		}
		
		/*
		 * Extracts key material and prepares signature keys.
		 * Public key blobs are defined in RFC4253, Section 6.6
		 * http://tools.ietf.org/html/rfc4253#section-6.6
		 * 
		 * @param key - DER encoded key material
		 */
		private void getKeyMaterial(byte[] key)
		{
			// Parse key material out of the DER encoded key
			DerDecoderPrivateKey decoder = new DerDecoderPrivateKey(method.toCU(), key);
			decoder.parse();
			
			if ( false == decoder.ready() )
			{
				// For now, just exit the function immediately.
				// No keys will be set, later resulting in authentication failure
				return;
			}
			
			pubkey = SshSignerHandler.preparePublic(method, decoder);
			kc = SshSignerHandler.preparePrivate(method, decoder);
			
			// checking of key assigning success? Not necessary right now
		}
		
		/*
		 * This method, required by interface, should check if the passphrase is correct.
		 * This class will always receive already decrypted key, so this method is
		 * not really necessary and will always return true.
		 * 
		 * @return always true
		 * 
		 * @throws JSchException - never thrown in this class
		 */
		public boolean setPassphrase(byte[] passphrase) throws JSchException
		{
			return true;
		}
		
		/*
		 * @return public key blob, ready to be sent to a SSH server
		 */
		public byte[] getPublicKeyBlob()
		{
			return pubkey;
		}
		
		/*
		 * This method performs digital signature. SSH standard requires method name to
		 * be prepended to the signature which is also done by this method.
		 * See RFC 4253, Section 6.6 for more information:
		 * http://tools.ietf.org/html/rfc4253#section-6.6
		 * 
		 * @return digital signature, ready to be sent to a SSH server
		 */
		public byte[] getSignature(byte[] data)
		{
			return SshSignerHandler.getSignature(kc, data);
		}
		
		/*
		 * This method is required by the interface but (probably) never called.
		 * Hence it always returns true.
		 * 
		 * @return always true
		 */
		public boolean decrypt()
		{
			return true;
		}
		
		/*
		 * @return Asymmetric algorithm name as defined by the SSH standard (RFC 4253)
		 */
		public String getAlgName()
		{
			return method.getName();
		}
		
		/*
		 * Identity name is used internally by the library routines.
		 * It can be set to anything.
		 * 
		 * @return an arbitrary string
		 */
		public String getName()
		{
			return "JschAuthBlobSigner";
		}
		
		/*
		 * This method is supposed to return information whether the private
		 * key is encrypted. It is not the case in this class, so false
		 * will be returned always.
		 * 
		 *  @return always false
		 */
		public boolean isEncrypted()
		{
			return false;
		}
		
		/*
		 * This method is supposed to cleanup the class before the identity is removed.
		 * It is not necessary to cleanup anything inside this class so the method is empty. 
		 */
		public void clear()
		{
			// nothing to do
		}
	}
}
