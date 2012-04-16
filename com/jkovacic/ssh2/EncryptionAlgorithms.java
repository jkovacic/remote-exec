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

/**
 * A class that groups lists of user approved encryption algorithms of an SSH session.
 * 
 * @author Jernej Kovacic
 *
 */
public class EncryptionAlgorithms 
{
	// to prevent some undesired manipulation (e.g. inserting the same algorithm several times),
	// lists are private and can be manipulated only using get/set methods
	private List<KexAlgs> kexAlgs;  // key exchange algorithms

	private List<Ciphers> cipherAlgs;  // symmetric cipher algorithms
	
	private List<Hmacs> hmacAlgs;  // HMAC (data integrity) algorithms
	
	private List<CompAlgs> compAlgs;  // compression algorithms
	
	/**
	 * Constructor.
	 * 
	 * It initializes all lists but does not fill any value.
	 * Use append* methods to actually insert algorithms.
	 */
	public EncryptionAlgorithms()
	{
		kexAlgs = new LinkedList<KexAlgs>();
		cipherAlgs = new LinkedList<Ciphers>();
		hmacAlgs = new LinkedList<Hmacs>();
		compAlgs = new LinkedList<CompAlgs>();
	}
	
	/**
	 * @return list of key exchange algorithms
	 */
	public List<KexAlgs> getKexAlgorithms()
	{
		return kexAlgs;
	}
	
	/**
	 * @return list of symmetric cipher algorithms
	 */
	public List<Ciphers> getCipherAlgorithms()
	{
		return cipherAlgs;
	}
	
	/**
	 * @return list of HMAC (data integrity) algorithms
	 */
	public List<Hmacs> getHmacAlgorithms()
	{
		return hmacAlgs;
	}
	
	/**
	 * @return list of compression algorithms
	 */
	public List<CompAlgs> getCompressionAlgorithms()
	{
		return compAlgs;
	}
	
	/*
	 * A utility function that checks if the specified algorithm already exists in the list.
	 * If not, it is appended to the end of the list.
	 * 
	 * Using generic programming (templating) it is possible to implement the function
	 * only once and use it for all families of algorithms (derived from IEncryptionAlgorithmFamily).
	 * This way it is much easier to maintain the code.
	 * 
	 * @param  list - list where the algorithm will be appended to
	 * @param  alg - algorithm to insert
	 */
	private <T extends ISshEncryptionAlgorithmFamily> void appendAlgorithm(List<T> list, T alg)
	{
		// check of input parameters
		if ( null == list )
		{
			return;
		}
		
		boolean found = false;
		
		// try to find the desired algorithm in the list
		for ( T algorithm : list )
		{
			if ( algorithm.equals(alg) )
			{
				found = true;
				break;  // out of for
			}
		}
		
		// if not found in the list, append it
		if ( false == found )
		{
			list.add(alg);
		}
	}
	
	/**
	 * Appends a key exchange algorithm into the list (if it does not exist yet)
	 * 
	 * @param alg - a key exchange algorithm to be appended
	 */
	public void appendKex(KexAlgs alg)
	{
		appendAlgorithm(kexAlgs, alg);
	}
	
	/**
	 * Appends a symmetric cipher algorithm into the list (if it does not exist yet)
	 * 
	 * @param alg - a symmetric cipher algorithm to be appended
	 */
	public void appendCipher(Ciphers alg)
	{
		appendAlgorithm(cipherAlgs, alg);
	}
	
	/**
	 * Appends a HMAC (data integrity) algorithm into the list (if it does not exist yet)
	 * 
	 * @param alg - a HMAC algorithm to be appended
	 */
	public void appendHmac(Hmacs alg)
	{
		appendAlgorithm(hmacAlgs, alg);
	}
	
	/**
	 * Appends a compression algorithm into the list (if it does not exist yet)
	 * 
	 * @param alg - a compression algorithm to be appended
	 */
	public void appendComp(CompAlgs alg)
	{
		appendAlgorithm(compAlgs, alg);
	}
	
}
