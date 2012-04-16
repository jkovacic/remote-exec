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

import java.util.Arrays;

/**
 * Abstract class with user authentication data. Details depend on 
 * an authentication method as implemented in derived classes
 * 
 * @author Jernej Kovacic
 *
 * @see UserCredentialsPassword, UserCredentialsPrivateKey
 */
public abstract class UserCredentials 
{
	// Username
	protected String username;
	
	// Password or DER encoded RSA or DSA private key
	protected byte[] secret = null;
	
	/**
	 * @return user name
	 */
	public String getUsername()
	{
		return this.username;
	}
	
	/**
	 * @return authentication secret (password or private key) depending on instantiated derived class
	 */
	public byte[] getSecret()
	{
		return this.secret;
	}
	
	/**
	 * Sets user name
	 * 
	 * @param uname - user name
	 */
	public void setUsername(String uname)
	{
		this.username = uname;
	}
	
	/**
	 * Secret contains confidential and sensitive data which should be overridden
	 * (overwritten) as soon as not needed any more. This can be done by this method.
	 * 
	 * It is also called by the destructor.
	 */
	public void overrideSecret()
	{
		if ( null!=secret )
		{
			Arrays.fill(secret, (byte) 0);
		}		
	}
	
	/*
		Destructor.
		
		When an object is to be destructed, it will make sure,
		that sensitive data (e.g. passwords, private keys) are
		overridden with zeros and as such not available to other
		objects that are allocated this object's memory
		
		@throws Throwable
	*/
	protected void finalize() throws Throwable 
	{
	    try 
	    {
	    	overrideSecret();
	    } 
	    finally 
	    {
	        super.finalize();
	    }
	}
}
