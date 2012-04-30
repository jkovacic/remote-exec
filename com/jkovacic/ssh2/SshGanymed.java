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

import com.jkovacic.cli.*;
import com.jkovacic.cryptoutil.*;

import java.io.*;
import java.util.*;

import ch.ethz.ssh2.*;

/**
  * Implementation of Ssh2 using an open source (BSD style license)
  * library GanymedSSH2. More info: http://www.cleondris.ch/opensource/ssh2/
  *
  * This implementation was developed on build 250.
  * 
  * @author Jernej Kovacic
*/
public final class SshGanymed extends Ssh2
{
	// Available algorithms, available via static methods of Connection:
	private static final String[] AVAILABLE_KEX_ALGS =
		{ 
		"diffie-hellman-group-exchange-sha1", 
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1"
        };
	
	private static final String[] AVAILABLE_HMAC_ALGS = Connection.getAvailableMACs();
	
	private static final String[] AVAILABLE_CIPHER_ALGS = Connection.getAvailableCiphers();
		
	private static final String[] AVAILABLE_PK_ALGS = Connection.getAvailableServerHostKeyAlgorithms();
	
	// The library does not support compression
	private static final String[] AVAILABLE_COMP_ALGS =
		{
		"none"
		};
		
	// Ganymed SSH connection context
	private Connection sshconn = null;
	

	/*
	 * Constructor 
	 * 
	 * @param host - a class with SSH server data
	 * @param user - user's data needed for authentication
	 * @param algorithms - selected encryption algorithms
	 */
	SshGanymed(HostId host, UserCredentials user, EncryptionAlgorithms algorithms)
	{
		super(host, user, algorithms);
		
		// Supported algorithms, available via static methods of Connection:
		
		/*
		 As evident from the source code, Ganymed SSH supports the following key exchange algorithms.
		 However it does not allow to choose preferred algorithms. For that reason we will just check if any
		 user selected KEX algorithm matches the available ones.
		 */ 
		availableKexAlgs = AVAILABLE_KEX_ALGS;
		
		// Hmac algorithms supported by the library
		availableHmacAlgs = AVAILABLE_HMAC_ALGS;
		
		// Cipher algorithms supported by the library
		availableCipherAlgs = AVAILABLE_CIPHER_ALGS;

		// Public key algorithms supported by the library
		availablePublickeyAlgs = AVAILABLE_PK_ALGS;
		
		// The library does not support compression
		availableCompAlgs = AVAILABLE_COMP_ALGS;
	}
	
		
	/*
	 * Performs password based authentication
	 * 
	 * @throws IOException (thrown by the library) if authentication fails
	 */
	private boolean authenticate(UserCredentialsPassword user) throws IOException
	{
		
		// GanymedSSH2 requires a password as a String.
		// However, String is immutable so it is not possible to 
		// overwrite its characters when they are not needed anymore.
		
		// Least we can do is to use StringBuffer (which is mutable)
		// and override its characters as soon as not needed anymore.
		StringBuffer password = new StringBuffer(user.secret.length);
		
		// copy password characters into a String buffer
		for ( byte b : user.secret )
		{
			password.append((char) b);
		}

		// And attempt to authenticate
		boolean authSucc = sshconn.authenticateWithPassword(user.username, password.toString());
		
		// before proceeding override the password with 'zero' characters
		for ( int i=0; i<user.secret.length; i++ )
		{
			password.setCharAt(i, '\u0000');
		}
		
		// and return the authentication success
		return authSucc;
	}
	
	/*
	 * Performs public key based authentication
	 * 
	 * @throws IOException (thrown by the library) if authentication fails
	 */
	private boolean authenticate(UserCredentialsPrivateKey user) throws IOException
	{
		/*
		 * NOTE: it looks like Ganymed SSH2 has problems with DSA based authentcation.
		 * Need to research the issue further.
		 * RSA based authentication works fine.
		 */
		String header = null;
		String footer = null;
		
		// GanymedSSH2 requires a PEM encoded private key.
		// Class Base64 has all appropriate functionality to prepare it.
		
		// First prepare an appropriate header and footer 
		if ( PKAlgs.DSA == user.getMethod() )
		{
			header = "-----BEGIN DSA PRIVATE KEY-----";
			footer = "-----END DSA PRIVATE KEY-----";
		}
		else
		{
			header = "-----BEGIN RSA PRIVATE KEY-----";
			footer = "-----END RSA PRIVATE KEY-----";
		}
		// TODO: Elliptic curve signature algorithms!
		
		// ... and prepare a PEM structure.
		// Note that the library is flexible about the line length and line separators
		char[] pem = Base64.encode(user.secret, 64, "\n", header, footer);
		
		// And attempt to authenticate
		boolean authSucc = sshconn.authenticateWithPublicKey(user.username, pem, null);
		
		// cleanup pem when not needed anymore!!!!
		Arrays.fill(pem, '\u0000');
		
		return authSucc;
	}
	
	/**
	 * Establish a connection to a SSH server
	 * 
	 * @throws SshException if the connection fails for any reason
	 */
	public void connect() throws SshException
	{
		// thoroughly check all settings
		shortlistAndCheckAlgorithms();
		checkUserSettings();
		checkDestHostSettings();
	
		// does an instance of Connection already exist?
		if ( null != sshconn &&  true == isConnected )
		{
			// a connection already exists, nothing to do
			return;
		}
	
		try
		{
			// if an inactive connection exists, destroy it and
			// create a new one
			sshconn = null;
			isConnected = false;
			
			// Instantiate a Connection class...
			sshconn = new Connection(destination.hostname, destination.port);
			
			// and set user selected algorithms (where the library allows it)
			sshconn.setClient2ServerCiphers(cipherAlgs);
			sshconn.setServer2ClientCiphers(cipherAlgs);
			sshconn.setClient2ServerMACs(hmacAlgs);
			sshconn.setServer2ClientMACs(hmacAlgs);
			
			// GanymedSSH API does not allow to set KEX and compression algorithms
			
			// finally try to establish the connection
			sshconn.connect(new StrictHostkeyVerifier(destination.hostkeys));
		}
		catch ( IOException ex )
		{
			// Something failed
			throw new SshException("SSH connection failed: '" + ex.getMessage() + "'");
		}
		
		try
		{
			// If reaching this point, the connection is established and key exchange was successful.
			// Now attempt to authenticate
			boolean userAuthSucc = false;
			
			// the auth. method depends on actual credentials
			if ( UserCredentialsPassword.class == user.getClass() )
			{
				// is this auth. method available?
				if ( false == sshconn.isAuthMethodAvailable(user.username, "password") )
				{
					throw new SshException("Password authentication not available for '" + user.username + "'");
				}
				
				userAuthSucc = authenticate((UserCredentialsPassword) user);
			}
			else if ( UserCredentialsPrivateKey.class == user.getClass() )
			{
				// is this auth. method available?
				if ( false == sshconn.isAuthMethodAvailable(user.username, "publickey") )
				{
					throw new SshException("Public key authentication not available for '" + user.username + "'");
				}
				
				userAuthSucc = authenticate((UserCredentialsPrivateKey) user);
			}
			// 'else' not necessary as userAuthSucc will be false and an exception will be thrown
			
			if ( false == userAuthSucc )
			{
				// Authentication failed
				throw new SshException("SSH authentication unsuccessful");
			}
			
			if ( false == sshconn.isAuthenticationComplete() )
			{
				throw new SshException("User authentication still incomplete");
			}
		}
		catch ( IOException ex )
		{
			// thrown by GanymedSSH2 methods
			throw new SshException("SSH authentication failed: '" + ex.getMessage() + "'");
		}
		
		// set the internal state
		isConnected = true;
	}
	
	/**
	 * Terminate the SSH connection
	 * 
	 * @throws SshException if it fails
	 */
	public void disconnect() throws SshException
	{
		if ( null != sshconn )
		{
			sshconn.close();
		}
		// Connection data not needed anymore, let the GC cleanup the structures:
		sshconn = null;
		
		isConnected = false;
	}
	
	/**
	 * Execute a command over SSH 'exec'
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
		Session sess = null;
		
		// check of input parameters
		if ( null == command || 0 == command.length() )
		{
			throw new SshException("No command specified");
		}
		
		// is connection established
		if ( null == sshconn || false == isConnected )
		{
			throw new SshException("SSH connection not established");
		}
		
		try
		{
			// Note that channel is called a "Session" by GanymedSSH2
			// Its API for execution of commands is very simple
			sess = sshconn.openSession();
			sess.execCommand(command);
			
			// get output
			try
			{
				// use CliUtil functionality to process the output
				retVal = processor.process(sess.getStdin(), new StreamGobbler(sess.getStdout()), new StreamGobbler(sess.getStderr()) );
			}
			catch ( CliException ex )
			{
				throw new SshException("Processing of output streams failed: " + ex.getMessage());
			}
			
			// wait until the command execution completes
			sess.waitForCondition(
					ChannelCondition.CLOSED & 
					ChannelCondition.EXIT_SIGNAL &
					ChannelCondition.EXIT_STATUS,
                    0);
			
			// command exit status is returned as Integer
			Integer exitStatus = sess.getExitStatus();
			
			// some SSH servers may not return it, set to 0 in this case
			if ( null == exitStatus )
			{
				retVal.exitCode = 0; // default value when not available
			}
			else
			{
				retVal.exitCode = exitStatus.intValue();
			}
			
			// and finally close the session
			sess.close();
		}
		catch ( IOException ex )
		{
			throw new SshException("Could not establish a SSH exec channel");
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
	 * An internal class implementing GanymedSSH2's interface ServerHostKeyVerifier.
	 * It is required by the library when authenticating a SSH server.
	 * 
	 * This class compares either public keys or their hashes (MD5 or Bubble Babble),
	 * depending on the HostkeyType of each known host key.
	 * 
	 * As the application is designed for automated sessions, very strict check
	 * is implemented, i.e. host keys or their hot finger prints must match any of user specified keys.
	 * In any other case (a different host key, host key not found yet), the session will fail.
	 */
	
	class StrictHostkeyVerifier implements ServerHostKeyVerifier
	{
		HostkeyVerifier verifier = null;
		
		/*
		 *  constructor that initializes the internal list of host keys
		 *  
		 *  @param keylist
		 */
		StrictHostkeyVerifier(List<Hostkey> keylist)
		{
			verifier = new HostkeyVerifier(keylist);
		}
		
		/*
		 * Implementation of the SeverHostKeyVerifier's (an interface provided by the GanymedSSH2 library) 
		 * only declared method. See Ganymed documentation for more info.
		 * 
		 * @see ch.ethz.ssh2.ServerHostKeyVerifier#verifyServerHostKey(java.lang.String, int, java.lang.String, byte[])
		 */
		public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) throws Exception
		{
			// As the external host verifying class already contains keys
			// for the right destination hosts,
			// hostname and port will be ignored
			return verifier.strictVerify(serverHostKeyAlgorithm, serverHostKey);
		}
	}
	
}
