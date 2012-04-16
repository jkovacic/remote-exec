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

/**
 * Class to represent servers' host keys, either as a public key or a finger print
 * (MD5 or bubble babble). Additionally includes information about the public key 
 * encryption algorithm used.
 * 
 * @author Jernej Kovacic
 *
 */
public class Hostkey 
{
	private PKAlgs method;
	
	private	byte[] hkey;
	
	private HostkeyType type;
	
	/*
	 * Checks input parameters and sets the appropriate fields
	 * 
	 * @param method - public key encryption method
	 * @param pubkey - public key
	 * 
	 * @throws SshException when inappropriate input parameters
	 */
	private void setParams(PKAlgs method, byte[] pubkey, HostkeyType hktype) throws SshException
	{
		if ( null == method )
		{
			throw new SshException("Public key algorithm not specified");
		}
		if ( null == pubkey )
		{
			throw new SshException("Public key not specified");
		}
		if ( null == hktype )	
		{
			throw new SshException("Host key type not specified");
		}
		
		this.method = method;
		this.hkey = pubkey.clone();
		this.type = hktype;
	}
	
	
	/**
	 * Constructor that sets public key encryption algorithm and the public key 
	 * Host key type will be set to "full key" by default.
	 * 
	 * @param method - public key encryption algorithm
	 * @param publicKey - public key 
	 * 
	 * @throws SshException when inappropriate input parameters are passed
	 */
	public Hostkey(PKAlgs method, byte[] publicKey) throws SshException
	{
		setParams(method, publicKey, HostkeyType.FULL_KEY);
	}
		
	/**
	 * Constructor that sets public key encryption algorithm and the public key 
	 * 
	 * @param method - public key encryption algorithm
	 * @param publicKey - DER encoded public key or a finger print (depending on 'hktype')
	 * @param hktype - type of the host key (full key, MD5 or bubble babble hash)
	 * 
	 * @throws SshException when inappropriate input parameters are passed
	 */
	public Hostkey(PKAlgs method, byte[] publicKey, HostkeyType hktype) throws SshException
	{
		setParams(method, publicKey, hktype);
	}
	
	/**
	 * @return public key
	 */
	public byte[] getHostPublicKey()
	{
		return this.hkey;
	}
	
	/**
	 * @return key's public key encryption algorithm
	 */
	public PKAlgs getMethod()
	{
		return this.method;
	}
	
	/**
	 * @return type of the host key (full key or one of its finger print representations)
	 */
	public HostkeyType getType()
	{
		return this.type;
	}
	
	
	/**
	 *  Type of the host key. Can be a MD5 or Bubble-Babble hash
	 *  or the whole public key.
	 *  Implemented as a simple Enum.
	 */
	public static enum HostkeyType
	{
		MD5,
		BUBBLE_BABBLE,
		FULL_KEY;
	}
	
	/*
	 * In SSH software, Bubble Babble is a "human readable" representation of a SHA-1 hash.
	 * More info about this encoding: 
	 * - http://wiki.yak.net/589
	 * - http://wiki.yak.net/589/Bubble_Babble_Encoding.txt
	 */
}
