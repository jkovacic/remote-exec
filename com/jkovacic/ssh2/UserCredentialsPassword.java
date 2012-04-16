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
 * User data for password based authentication to a SSH server
 * 
 * @author Jernej Kovacic
 *
 * @see UserCredentials
 */
public class UserCredentialsPassword extends UserCredentials 
{
	/**
	 * Sets user's password.
	 * 
	 * Note that String is immutable and as such inappropriate to hold sensitive data
	 * as password is. That is why an array of chars is encouraged. If you insist on
	 * String based passwords, just call password.toCharArray()
	 * 
	 * @param sec - password as an array of chars
	 */
	public void setSecret(char[] sec)
	{
		int seclength = ( null==sec ? 0 : sec.length );
			
		this.secret = new byte[seclength];
		for ( int i=0; i<seclength; i++ )
		{
			this.secret[i] = (byte) sec[i];
		}
	}
}
