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

import com.jkovacic.cryptoutil.*;


/**
 * Supported HMAC (message integrity) algorithms.
 * 
 * If any algorithm is to be added (or removed) it is done only once.
 * The implementation methods are robust enough to handle this change
 * automatically without the need for any additional change. 
 * 
 * @author Jernej Kovacic
 *
 * @see ISshEncryptionAlgorithmFamily
 */

public enum Hmacs implements ISshEncryptionAlgorithmFamily, ISshMarshalledAlgorithm
{
	SHA1("hmac-sha1", DigestAlgorithm.SHA1),
	MD5("hmac-md5", DigestAlgorithm.MD5),
	SHA1_96("hmac-sha1-96", null),
	MD5_96("hmac-md5-96", null),
	RIPEMD160("hmac-ripemd160", null),
	RIPEMD160_96("hmac-ripemd160-96", null),
	NONE("none", null);
	
	private String name;
	private DigestAlgorithm cu = null;
	
	Hmacs(String name, DigestAlgorithm generalAlg)
	{
		this.name = name;
		this.cu = generalAlg;
	}
	
	/**
	 * @return name of the algorithm as defined by SSH2 hand shaking and key exchange protocols
	 */
	public String getName()
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
	public static Hmacs getAlg(String name) throws SshException
	{
		// For purposes of easier maintainability, apply a generic function,
		// appropriate for all families of encryption algorithms
		return GenericLookupUtil.lookupByName(Hmacs.values(), name);
	}
	
	/**
	 * Convert into an instance of DigestAlgorithm
	 * 
	 * @return instance of DigestAlgorithm if conversion is possible, null if not
	 */
	public DigestAlgorithm toCU()
	{
		return this.cu;
	}
	
	/**
	 * Converts an instance of DigestAlgorithm into its "counterpart" of Hmacs
	 * 
	 * @param cuAlg - an instance of DigestAlgorithm to be converted
	 * 
	 * @return appropriate conversion of cuAlg if possible, null otherwise
	 */
	public static Hmacs fromCU(DigestAlgorithm cuAlg)
	{
		return GenericLookupUtil.lookupByCUType(Hmacs.values(), cuAlg);
	}
}
