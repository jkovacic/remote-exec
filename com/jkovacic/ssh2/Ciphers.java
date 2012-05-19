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

import com.jkovacic.util.*;

/**
 * Supported symmetric cipher algorithms.
 * 
 * If any algorithm is to be added (or removed) it is done only once.
 * The implementation methods are robust enough to handle this change
 * automatically without the need for any additional change. 
 * 
 * @author Jernej Kovacic
 *
 * @see ISshEncryptionAlgorithmFamily
 */
public enum Ciphers implements ISshEncryptionAlgorithmFamily
{
	AES256_CTR("aes256-ctr"),
	AES256_CBC("aes256-cbc"),
	TWOFISH256_CTR("twofish256-ctr"),
	TWOFISH256_CBC("twofish256-cbc"),
	AES192_CTR("aes192_ctr"),
	AES192_CBC("aes192-cbc"),
	AES128_CTR("aes128-ctr"),
	AES128_CBC("aes128-cbc"),
	TWOFISH128_CTR("twofish128-ctr"),
	TWOFISH128_CBC("twofish128-cbc"),
	BLOWFISH_CTR("blowfish-ctr"),
	BLOWFISH_CBC("blowfish-cbc"),
	TRIPPLE_DES_CTR("3des-ctr"),
	TRIPPLE_DES_CBC("3des-cbc"),
	RC4("arcfour"),
	CAST128_CTR("cast128-ctr"),
	CAST128_CBC("cast128-cbc"),
	NONE("none");
	
	private String name;
	
	Ciphers(String name)
	{
		this.name = name;
	}
	
	/**
	 * @return name of the algorithm as defined by SSH2 hand shaking and key exchange protocols
	 */	
	public String getValue()
	{
		return this.name;
	}
	
	/**
	 * Lookup the algorithm specified by its standardized name
	 * 
	 * @param name - string to look up
	 * @return instance of the requested algorithm
	 * @throws SshException when name could not be resolved
	 */
	public static Ciphers getAlg(String name) throws SshException
	{
		// For purposes of easier maintainability, apply a generic function,
		// appropriate for all families of encryption algorithms
		Ciphers retVal = LookUpUtil.lookUp(Ciphers.values(), name);
		
		if ( null==retVal )
		{
			throw new SshException("Name not found");
		}
		
		return retVal;
	}
	
}
