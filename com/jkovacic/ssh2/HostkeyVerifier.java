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
import java.security.*;

import com.jkovacic.cryptoutil.*;

/**
 * Implementation of a host key checking. 
 * Typically SSH libraries declare an interface of a host key checking class
 * that must be implemented. All such implementations will use this class.
 * 
 * @author Jernej Kovacic
 */
class HostkeyVerifier 
{
	private List<Hostkey> knownKeys = null;
	
	/*
	 *  constructor that initializes the internal list of host keys
	 *  
	 *  @param keylist
	 */
	protected HostkeyVerifier(List<Hostkey> keylist)
	{
		this.knownKeys = keylist;
	}
	
	/**
	 * Checks if the host key (a public key) is listed among known host keys.
	 * 
	 * A strict check is performed, i.e. the check will pass only if the hkey
	 * and its encryption algorithm are known to the application. 
	 *
	 * Note, some SSH libraries (e.g. Jsch) do not pass the encryption algorithm.
	 * In such a case, the algorithm may be null and checking of the encryption
	 * algorithm will be skipped
	 * 
	 * @param algorithm - name of the encryption algorithm
	 * @param hkey - server host key
	 * @return true/false; is the hkey known to the application
	 */
	protected boolean strictVerify(String algorithm, byte[] hkey)
	{
		if ( null == hkey )
		{
			return false;
		}
		
		if ( null==knownKeys || 0==knownKeys.size() )
		{
			return false;
		}
		
		boolean retVal = false;
		MessageDigest md = null;
		String md5hash = null;
		String bbhash = null;
		
		// Calculate hkey's MD5 and Bubble - Babble hash
		try
		{
			byte[] digest = null;
			md =  MessageDigest.getInstance(DigestAlgorithm.MD5.getName());
			
			digest = md.digest(hkey);
			md5hash = new String(ByteHex.toHex(digest)); 
			md.reset();
			
			md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
			digest = md.digest(hkey);
			bbhash = new String(BubbleBabble.encode(digest));
		}
		catch ( NoSuchAlgorithmException ex )
		{
			System.err.println("Unknown algorithm");
			return false;
		}
		
		keyloop:
		for ( Hostkey key : knownKeys )
		{
			if ( null == key.getHostPublicKey() )
			{
				continue keyloop;
			}
			
			// if (key algorithm is specified (i.e. not null)
			// also check equality of algorithms.
			// If it is not specified skip this check (consider it as passed)
			if ( null != algorithm &&
					false == algorithm.equals(key.getMethod().getName()) )
			{
				// Different public key algorithms ==> not the right key
				continue keyloop;
			}
			
			byte[] hostkey = key.getHostPublicKey();
			char[] keyhash = null;
			String strhash = null;
			
			// in case if a key's finger print is provided,
			// convert it from byte[] to char[]...
			if ( Hostkey.HostkeyType.FULL_KEY != key.getType() )
			{
				keyhash = new char[hostkey.length];
				for ( int i=0; i<hostkey.length; i++)
				{
					keyhash[i] = (char) hostkey[i];
				}
				
				// and then to String
				strhash = new String(keyhash);
				
				// Finally compare finger prints
				// Note that hex values (used for MD5 representation) are case insensitive
				if ( ( Hostkey.HostkeyType.MD5 == key.getType() &&
					   md5hash.equalsIgnoreCase(strhash) ) || 
						  
					 ( Hostkey.HostkeyType.BUBBLE_BABBLE == key.getType() &&
					   bbhash.equals(strhash) ) ) 	
					{
						retVal = true;
						break keyloop;
					}
				
			}
			else if ( Hostkey.HostkeyType.FULL_KEY == key.getType() )
			{
				// If a full public key is provided,
				// compare keys byte by byte
				if ( hostkey.length != hkey.length )
				{
					// keys of different lengths cannot match
					continue keyloop;
				}
				
				for ( int i=0; i<hostkey.length; i++ )
				{
					if ( hostkey[i] != hkey[i] )
					{
						// keys do not match
						continue keyloop;
					}
				}
				
				retVal = true;
				break keyloop;
			}
			else
			{
				// unsupported key type
				continue;
			}
			
		}
		
		return retVal;
	}
}
