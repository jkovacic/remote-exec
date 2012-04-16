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

import java.util.*;

/**
 * An abstract class with some common (independent of the 3rd party library) 
 * SSH functionality. An actual class, based on a chosen crypto/SSH library
 * (e.g. GanymedSSH2, Jsch, etc.), must be derived from this one. 
 * 
 * Note, regardless of the chosen SSH library, problems with DSA private keys
 * were observed, unless the key pair was generated using JSch's KeyPair.genKeyPair()
 * and such not longer than 1024 bit.
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
	 * @param command - full command to execute, given as one line
	 * 
	 * @return an instance of CliOutput with results of the executed command
	 * 
	 * @throws CliException when execution fails for any reason
	 */
	public abstract CliOutput exec(String command) throws SshException;
	
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
		for ( Hostkey hk : destination.hostkeys )
		{
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
		}
		else
		{
			// Neither a password nor a PK auth method. Currently this is unsupported.
			throw new SshException("Unsupported authentication method");
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
		JSCH;       // Jsch (can be listed here even though not implemented yet)
	}
}
