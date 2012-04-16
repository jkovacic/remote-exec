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
 * This factory class is intended to be the only "legal" way
 * to create instances of Ssh2 (various classes with SSH functionality) 
 * 
 * Methods are static so no instantiation is necessary 
 * 
 * @author Jernej Kovacic
 */
public class SshFactory 
{
	/**
	 * Instantiates an instance of SshGynymed, a Ssh2 implementation
	 * based on the 3rd party library Ganymed SSH2.
	 * 
	 * @param host - a class with SSH server data
	 * @param user - user's data needed for authentication
	 * @param algorithms - selected encryption algorithms
	 * 
	 * @throws SshException if any SSH parameters are missing
	 */
	public static SshGanymed getGanymedInstance(HostId host, UserCredentials user, EncryptionAlgorithms algorithms) throws SshException
	{
		// check of input parameters
		if ( null==host || null==user || null==algorithms )
		{
			throw new SshException("Not all SSH parameters provided");
		}
		
		return new SshGanymed(host, user, algorithms);
	}
	
	/**
	 * Instantiates an instance of SshJsch, a Ssh2 implementation
	 * based on the 3rd party library Jsch.
	 * 
	 * @param host - a class with SSH server data
	 * @param user - user's data needed for authentication
	 * @param algorithms - selected encryption algorithms
	 * 
	 * @throws SshException if any SSH parameters are missing
	 */
	public static SshJsch getJschInstance(HostId host, UserCredentials user, EncryptionAlgorithms algorithms) throws SshException
	{
		// check of input parameters
		if ( null==host || null==user || null==algorithms )
		{
			throw new SshException("Not all SSH parameters provided");
		}
				
		return new SshJsch(host, user, algorithms);
	}
}
