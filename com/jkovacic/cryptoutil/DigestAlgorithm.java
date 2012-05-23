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
 * Supported digest (hashing) algorithms.
 * 
 * If any algorithm is to be added (or removed) it is done only once.
 * The implementation methods are robust enough to handle this change
 * automatically without the need for any additional change. 
 * 
 * @author Jernej Kovacic
 */
public enum DigestAlgorithm implements IEncryptionAlgorithmFamily
{
	MD5("MD5", "MD5"),
	SHA1("SHA-1", "SHA1"),
	SHA256("SHA-256", "SHA256"),
	SHA384("SHA-384", "SHA384"),
	SHA512("SHA-512", "SHA512");
	
	private String desc;
	private String compact;
	
	/*
	 * Constructor 
	 * 
	 * @param name of the algorithm
	 * @param "compact" name (without any hyphens) of the algorithm 
	 */
	private DigestAlgorithm(String name, String compact)
	{
		this.desc = name;
		this.compact = compact;
	}
	
	/**
	 * @return name of the algorithm as defined by most Java crypto providers
	 */
	public String getName()
	{
		return this.desc;
	}
	
	/**
	 * @return "compact" name of the algorithm, i.e. without any hyphens. This is necessary to instantiate digital signature or HMAC classes
	 */
	public String getCompact()
	{
		return this.compact;
	}
}
