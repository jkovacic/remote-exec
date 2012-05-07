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

package com.jkovacic.cryptoutil;

/**
 * Supported asymmetric cryptography (public key) algorithms.
 * 
 * If any algorithm is to be added (or removed) it is done only once.
 * The implementation methods are robust enough to handle this change
 * automatically without the need for any additional change. 
 * 
 * @author Jernej Kovacic
 */
public enum AsymmetricAlgorithm implements IEncryptionAlgorithmFamily
{
	DSA("DSA"),
	RSA("RSA"),
	ECDSA_NISTP256("ECDSA-P256"),
	ECDSA_NISTP384("ECDSA-P384"),
	ECDSA_NISTP521("ECDSA-P521");
	
	private String desc = null;
	
	/*
	 * Constructor
	 */
	private AsymmetricAlgorithm(String name)
	{
		this.desc = name;
	}
	
	/**
	 * @return name of the algorithm as defined by most Java crypto providers
	 */
	public String getName()
	{
		return this.desc;
	}
}
