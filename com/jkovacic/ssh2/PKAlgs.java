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
 * Supported asymmetric cryptography (public key) algorithms.
 * 
 * If any algorithm is to be added (or removed) it is done only once.
 * The implementation methods are robust enough to handle this change
 * automatically without the need for any additional change. 
 * 
 * @author Jernej Kovacic
 *
 * @see ISshEncryptionAlgorithmFamily
 */

public enum PKAlgs implements ISshEncryptionAlgorithmFamily, ISshMarshalledAlgorithm
{
	DSA("ssh-dss", AsymmetricAlgorithm.DSA),
	RSA("ssh-rsa", AsymmetricAlgorithm.RSA) ;
	
	private String name;
	
	private AsymmetricAlgorithm cu = null;
	
	PKAlgs(String name, AsymmetricAlgorithm generalAlg)
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
	public static PKAlgs getAlg(String name) throws SshException
	{
		// For purposes of easier maintainability, apply a generic function,
		// appropriate for all families of encryption algorithms
		return GenericLookupUtil.lookupByName(PKAlgs.values(), name);
	}
	
	/**
	 * Convert into an instance of AsymmetricAlgorithm
	 * 
	 * @return instance of AsymmetricAlgorithm if conversion is possible, null if not
	 */
	public AsymmetricAlgorithm toCU()
	{
		return this.cu;
	}
	
	/**
	 * Converts an instance of AsymmetricAlgorithm into its "counterpart" of PKAlgs
	 * 
	 * @param cuAlg - an instance of AsymmetricAlgorithm to be converted
	 * 
	 * @return appropriate conversion of cuAlg if possible, null otherwise
	 */
	public static PKAlgs fromGeneral(AsymmetricAlgorithm cuAlg)
	{
		return GenericLookupUtil.lookupByCUType(PKAlgs.values(), cuAlg);
	}
}
