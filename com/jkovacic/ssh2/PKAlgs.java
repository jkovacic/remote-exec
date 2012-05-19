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
import com.jkovacic.util.*;

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
	RSA("ssh-rsa", AsymmetricAlgorithm.RSA),
	ECDSA_NISTP256("ecdsa-sha2-nistp256", AsymmetricAlgorithm.ECDSA_NISTP256),
	ECDSA_NISTP384("ecdsa-sha2-nistp384", AsymmetricAlgorithm.ECDSA_NISTP384),
	ECDSA_NISTP521("ecdsa-sha2-nistp521", AsymmetricAlgorithm.ECDSA_NISTP521);
	
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
	public static PKAlgs getAlg(String name) throws SshException
	{
		// For purposes of easier maintainability, apply a generic function,
		// appropriate for all families of encryption algorithms
		PKAlgs retVal = LookUpUtil.lookUp(PKAlgs.values(), name);
		
		if ( null==retVal )
		{
			throw new SshException("Name not found");
		}
		
		return retVal;
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
		return AlgGenericLookupUtil.lookupByCUType(PKAlgs.values(), cuAlg);
	}
}
