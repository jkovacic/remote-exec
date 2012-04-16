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

package com.jkovacic.rclient;

/**
 * A class with necessary credentials to authenticate on a remote host
 * to perform a remote execution via rexec service.
 * 
 * @author Jernej Kovacic
 */
public class RexecCredentials extends RCredentials 
{
	/** Default rexec port */
	public static int DEFAULT_REXEC_PORT = 512;

	/*
	 * Password for authentication on the remote host.
	 * 
	 * As String is immutable in Java, it is implemented as an array of chars,
	 * this way it is possible to "erase" it as soon as it is not needed anymore.
	 */
	protected char[] password;
	
	/**
	 * Constructor (the only acceptable way to set members of the class)
	 * 
	 * @param hostname - host name of the remote host
	 * @param port - port on the remote host
	 * @param username - username to authenticate on the remote host
	 * @param password - password to authenticate on the remote host
	 */
	public RexecCredentials(String hostname, int port, String username, char[] password)
	{
		setCredentials(hostname, port, username, password);
	}
	
	/**
	 * Constructor (the only acceptable way to set members of the class)
	 * 
	 * The rexec default port will be set.
	 * 
	 * @param hostname - host name of the remote host
	 * @param username - username to authenticate on the remote host
	 * @param password - password to authenticate on the remote host
	 */
	public RexecCredentials(String hostname, String username, char[] password)
	{
		setCredentials(hostname, DEFAULT_REXEC_PORT, username, password);
	}
	
	/*
	 * Utility function to set members of the class.
	 * It should be called by constructors only.
	 */
	private void setCredentials(String hostname, int port, String username, char[] password)
	{
		this.hostname = hostname;
		this.port = port;
		this.username = username;
		this.password = password;
	}
	
	/**
	 * Overwrites the password with "zeros".
	 * 
	 * The method is recommended to be called as soon as the password is not needed anymore.
	 */
	public void overwritePassword()
	{
		// does the array of password chars exist?
		if ( null == password )
		{
			return;
		}
		
		// overwrite each character with a "zero" char
		for ( int i=0; i<password.length; i++ )
		{
			password[i] = '\u0000';
		}
	}
	
	/**
	 * Returns the password to authenticate on the remote server.
	 * 
	 * @return password as an array of chars
	 */
	public char[] getPassword()
	{
		return this.password;
	}
	
	/*
	Destructor.
	
	When an object is to be destructed, it will make sure,
	that sensitive data (e.g. a passwords) are
	overwritten with zeros and as such not available to other
	objects that are allocated this object's memory
	
	@throws Throwable
	*/
	protected void finalize() throws Throwable 
	{
	    try 
	    {
	    	overwritePassword();
	    } 
	    finally 
	    {
	        super.finalize();
	    }
	}
}
