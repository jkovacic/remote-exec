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

import java.util.*;

/**
 * An abstract class with some common (independent of the 3rd party library) 
 * SSH functionality. An actual class, based on a chosen crypto/SSH library
 * (e.g. GanymedSSH2, Jsch, etc.), must be derived from this one. 
 * 
 * @author Jernej Kovacic
 *
 * @see SshGanymed, SshJsch
 */

/*
 * If a need arises, other SSH functionality methods can be declared here,
 * e.g. port forwarding, SFTP file transfer, etc.
 * 
 * TODO Additionally key reexchange, sending keep alive messages, etc. could be implemented for longer sessions
 */

public abstract class Ssh2
{
	protected HostId destination;
	protected UserCredentials user;
	protected EncryptionAlgorithms algs;
	
	// available algorithms, dependent on the used SSH library and typically to be
	// assigned by derived classes' constructors
	protected String[] availableKexAlgs = null;
	protected String[] availableHmacAlgs = null;
	protected String[] availableCipherAlgs = null;
	protected String[] availablePublickeyAlgs = null;
	protected String[] availableCompAlgs = null;
	
	/* 
	 SSH standard (and also both supported SSH libraries) does allow different algorithms for each direction (client to server or vice versa).
	 However, this makes sense very rarely. Hence this example proposes the same set for both directions (as most SSH software does as well)	 
	 */
	protected String[] cipherAlgs = null;
	protected String[] hmacAlgs = null;
	protected String[] kexAlgs = null;
	protected String[] hostkeyAlgs = null;
	protected String[] compAlgs = null;
	
	// an internal state variable indicating whether a connection is established or not
	protected boolean isConnected = false;
	
	/**
	 * Establish a connection to a SSH server
	 * 
	 * @throws SshException if the connection fails for any reason
	 */
	public abstract void connect() throws SshException;
	
	/**
	 * Terminate the SSH connection
	 * 
	 * @throws SshException if it fails
	 */
	public abstract void disconnect() throws SshException;
	
	/*
	 * Constructor 
	 * 
	 * @param host - a class with SSH server data
	 * @param user - user's data needed for authentication
	 * @param algorithms - selected encryption algorithms
	 */
	protected Ssh2(HostId host, UserCredentials user, EncryptionAlgorithms algorithms)
	{
		this.destination = host;
		this.user = user;
		this.algs = algorithms;
		
		this.isConnected = false;
	}
	
	/**
	 * 
	 * @param host - a class with SSH server data
	 */
	public void setHost(HostId host)
	{
		this.destination = host;
	}
	
	/**
	 * 
	 * @param user - user's data needed for authentication
	 */
	public void setUserCredentials(UserCredentials user)
	{
		this.user = user;
	}
	
	/**
	 * 
	 * @param algorithms - selected encryption algorithms
	 */
	public void setAlgorithms(EncryptionAlgorithms algorithms)
	{
		this.algs = algorithms;
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
	public abstract CliOutput exec(ICliProcessor processor, String command) throws SshException;
	
	/*
	 * Calls acceptedSupportedAlgs for each family of encryption algorithms
	 * and thoroughly checks if at least one algorithm for each family has remained.
	 * 
	 *  @throws SshException if any check fails
	 */
	protected void shortlistAndCheckAlgorithms() throws SshException
	{
		if ( null == algs )
		{
			throw new SshException("Encryption algorithm settings not availble");
		}
			
		cipherAlgs = acceptedSupportedAlgs(algs.getCipherAlgorithms(), availableCipherAlgs);
		hmacAlgs = acceptedSupportedAlgs(algs.getHmacAlgorithms(), availableHmacAlgs);
		kexAlgs = acceptedSupportedAlgs(algs.getKexAlgorithms(), availableKexAlgs);
		compAlgs = acceptedSupportedAlgs(algs.getCompressionAlgorithms(), availableCompAlgs);
		
		// Hostkey (i.e. public - private key) algorithms
		
		if ( null == destination )
		{
			throw new SshException("Destination host details not availble");
		}
		
		if ( null == destination.hostkeys )
		{
			throw new SshException("Destination hostkeys not specified");
		}
		
		List<PKAlgs> pkalgs = new ArrayList<PKAlgs>();
		hkloop:
		for ( Hostkey hk : destination.hostkeys )
		{
			// check if the algorithm already is in the list
			for ( PKAlgs tempalg : pkalgs )
			{
				if ( hk.getMethod()==tempalg )
				{
					// the lagorithm already is in the list, continue with the external loop
					continue hkloop;
				}
			}
			
			// if reaching this point, the algorithm is not yet 
			// a member of pkalgs, insert it:
			pkalgs.add(hk.getMethod());
		}
		hostkeyAlgs = acceptedSupportedAlgs(pkalgs, availablePublickeyAlgs);
		
		// Check if at least one algorithm among available ones was selected for each family.
		if ( null==cipherAlgs || 0==cipherAlgs.length )
		{
			throw new SshException("None of available cipher algorithms selected");
		}
		
		if ( null==hmacAlgs || 0==hmacAlgs.length )
		{
			throw new SshException("None of available HMAC algorithms selected");
		}
		
		if ( null==kexAlgs || 0==kexAlgs.length )
		{
			throw new SshException("None of available key exchange algorithms selected");
		}
		
		if ( null==hostkeyAlgs || 0==hostkeyAlgs.length )
		{
			throw new SshException("None of available hostkey algorithms selected");
		}
		
		if ( null==compAlgs || 0==compAlgs.length )
		{
			throw new SshException("None of availble compression algorithms selected");
		}

	}
	
	/*
	 * Picks those user selected algorithms that are also supported by the SSH library.
	 * As order is important on the client side, the user defined order of algorithms is preserved.
	 * 
	 * Utilizing generic programming ("templating"), this utility function is written only once and
	 * applicable for any algorithm family derived from IEncryptionAlgorithmFamily.
	 * This way the code is much easier to maintain.
	 * 
	 * @param allowed - user selected encryption algorithms
	 * @param available - SSH library's supported encryption algorithms
	 * 
	 * @return list of those user selected algorithms that are supported by the SSH library, user defined order is preserved
	 */
	protected <T extends ISshEncryptionAlgorithmFamily> String[] acceptedSupportedAlgs(List<T> allowed, String[] available)
	{
		List<String> proposed = new ArrayList<String>();
		
		/*
		 All user approved algorithms are checked for availability in the selected SSH library.
		 Those not listed among available ones are excluded. Please note that the order on a client 
		 side IS important as it actually determines selected algorithms during key exchange.
		 Hence the order of the user supplied algorithms is preserved.
		*/ 
		
		// each user selected algorithm...
		for ( T alg : allowed )
		{
			String name = alg.getName();
			
			// is searched among supported ones by its string name (as defined by SSH standards)
			for ( String av : available )
			{
				// if it is found it can be included among selected ones
				if ( name.equalsIgnoreCase(av) )
				{
					// for a (bit) improved robustness include the name as defined by the SSH library
					proposed.add(av);
					break; // out of for av
				}
			}  // for av
		}  // for alg
		
		return (String[]) proposed.toArray(new String[0]);
	}
	
	
	/*
	 * Thorough and strict check of user credential data
	 * 
	 * @throws SshException if any check fails
	 */
	protected void checkUserSettings() throws SshException
	{
		if ( null == user )
		{
			throw new SshException("User settings not availble");
		}
		
		// username must not be an empty string
		String username = user.getUsername();
		if ( null==username || 0==username.length() )
		{
			throw new SshException("Username not provided");
		}
		
		// secret must not be an empty string
		byte[] sec = user.getSecret();
		if ( null==sec || 0==sec.length )
		{
			throw new SshException("No secret provided");
		}
		
		
		if ( UserCredentialsPassword.class == user.getClass() )
		{
			// nothing to check further
		}
		else if ( UserCredentialsPrivateKey.class == user.getClass() )
		{
			// additionally check for PK method
			UserCredentialsPrivateKey upk = (UserCredentialsPrivateKey) user;
			if ( null == upk.getMethod() )
			{
				throw new SshException("No public key method provided");
			}
			
			if ( PKAlgs.DSA == upk.getMethod() )
			{
				checkDsaKey(upk.getSecret());
			}
		}
		else
		{
			// Neither a password nor a PK auth method. Currently this is unsupported.
			throw new SshException("Unsupported authentication method");
		}
	}
	
	/*
	 * Checks if the DSA key will produce a signature of proper size.
	 * 
	 * @param dsakey - DER encoded DSA private key
	 * 
	 * @throws SshException in case of inappropriate key parameters
	 */
	private void checkDsaKey(byte[] dsakey) throws SshException
	{
		// check of input parameter
		if ( null == dsakey )
		{
			throw new SshException("Could not check a DSA key");
		}
		
		/*
		 * For DSA signatures, SSH standard (RFC 4253) strictly requires 40 byte signature
		 * blobs. Typically this is a case for 1024-bit DSA keys. If a longer DSA key pair is properly 
		 * generated, its subprime (Q) would be longer, resulting in longer signatures which is not
		 * supported by the SSH specifications. However, some key generators (e.g. Putty or OpenSSH) can generate
		 * longer DSA keys with shorter Q that can generate short enough signatures to perform authentication.
		 * In other words, it is possible to use "adapted" DSA keys longer than 1024-bit, however such keys are not
		 * stronger than 1024-bit keys. More info about this at:
		 * https://fogbugz.bitvise.com/default.asp?Tunnelier.2.5037.1 
		 * 
		 * This method will parse the DSA key and check if size of the Q parameter is appropriate.
		 */
		DerDecoderPrivateKey decoder = new DerDecoderPrivateKey(PKAlgs.DSA.toCU(), dsakey);
		decoder.parse();
		if ( false == decoder.ready() )
		{
			throw new SshException("Invalid DSA key");
		}
		
		/*
		 * The DSA digital signature consists of two elements: r and s.
		 * As it is obvious from this article:
		 * http://en.wikipedia.org/wiki/Digital_Signature_Algorithm
		 * Q is a modulo in equations for both elements and as such it determines
		 * their size. For that reason, Q will be parsed from the private key and 
		 * its size will be checked. It must not exceed 20 bytes (or additional byte
		 * determining its sign).
		 */
		byte[] q = decoder.get('q');
		if ( null == q )
		{
			throw new SshException("Could not parse the DSA Q parameter");
		}
		
		if ( !( 20==q.length || 21==q.length) )
		{
			throw new SshException("Unsupported DSA key size");
		}
		
		/*
		 * If the MSB of the actual Q is 1, the whole parameter would be negative,
		 * hence additional 0-byte is prepended to it. In this case Q must be 21
		 * bytes long, the first byte must equal 0 and the next byte must be "negative"
		 */
		if ( !( (20==q.length && q[0]<0) ||
			    (21==q.length && 0==q[0] && q[1]<0) ) )  
		{
			throw new SshException("Unsupported DSA key size");
		}
	}
	
	/*
	 * Thorough and strict check of SSH server data
	 * 
	 * @throws SshException if any check fails
	 */
	protected void checkDestHostSettings() throws SshException
	{
		if ( null == destination )
		{
			throw new SshException("Destination host details not availble");
		}
		
		if ( null==destination.hostname || 0==destination.hostname.length() )
		{
			throw new SshException("Destination address not specified");
		}
		
		// Any port number will be accepted ==> no checking
		
		// host keys prevent possibilities of MITM attacks,
		// so at least one non empty public key must be provided
		if ( null==destination.hostkeys || 0==destination.hostkeys.size() )
		{
			throw new SshException("Destination hostkeys not specified");
		}
		
		for ( Hostkey key : destination.hostkeys )
		{
			if ( null == key )
			{
				throw new SshException("Undefined hostkey");
			}
			
			if ( null == key.getMethod() )
			{
				throw new SshException("Hostkey method not specified");
			}
			
			byte[] hkey = key.getHostPublicKey();
			if ( null==hkey || 0==hkey.length )
			{
				throw new SshException("Hostkey not specified");
			}
		}
	}
	
	/**
	 * Returns information whether the SSH connection is still available.
	 * 
	 * @return true/false
	 */
	public boolean isConnected()
	{
		return isConnected;
	}
	
	
	/**
	 * Supported implementations of classes with implemented SSH functionality
	 * (derived from this one).
	 * 
	 * At the moment only Ganymed SSH2 and Jsch are supported.
	 */
	public static enum SshImpl
	{
		GANYMED,	// Ganymed SSH2
		JSCH;       // Jsch
	}
}
