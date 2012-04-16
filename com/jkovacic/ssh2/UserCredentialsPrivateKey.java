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
 * User data for public key based authentication to a SSH server
 * 
 * @author Jernej Kovacic
 *
 * @see UserCredentials
 */
public class UserCredentialsPrivateKey extends UserCredentials 
{
	private PKAlgs method = null;  // additional field with the PK encryption algorithm
	
	/**
	 * Sets the private key
	 * 
	 * @param sec - private key
	 */
	public void setSecret(byte[] sec) 
	{
		this.secret = sec;
	}

	/**
	 * Returns encryption algorithm for the private key
	 * 
	 * @return public key encryption algorithm
	 */
	public PKAlgs getMethod()
	{
		return this.method;
	}
	
	/**
	 * Sets the encryption algorithm for the private key
	 * 
	 * @param method - public key encryption algorithm
	 */
	public void setMethod(PKAlgs method)
	{
		this.method = method;
	}

}
