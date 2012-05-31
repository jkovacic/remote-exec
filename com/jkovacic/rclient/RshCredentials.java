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
 * to perform a remote execution via rsh/rlogin service.
 * 
 * @author Jernej Kovacic
 */
public class RshCredentials extends RCredentials 
{
	/** Default rsh port */
	public static final int DEFAULT_RSH_PORT = 514;

	/*
	 * Username on thee local host. It is required for successful rsh host based authentication
	 */
	protected String localUsername;
	
	/**
	 * Constructor (the only acceptable way to set members of the class)
	 * 
	 * @param hostname - host name of the remote host
	 * @param port - port on the remote host
	 * @param remoteusername - username to authenticate on the remote host
	 * @param localUsername - username on the local host
	 */
	public RshCredentials(String hostname, int port, String remoteUsername, String localUsername)
	{
		setCredentials(hostname, port, remoteUsername, localUsername);
	}
	
	/**
	 * Constructor (the only acceptable way to set members of the class)
	 * 
	 * Port will be set to the default value.
	 * 
	 * @param hostname - host name of the remote host
	 * @param remoteusername - username to authenticate on the remote host
	 * @param localUsername - username on the local host
	 */
	public RshCredentials(String hostname, String remoteUsername, String localUsername)
	{
		setCredentials(hostname, DEFAULT_RSH_PORT, remoteUsername, localUsername);
	}
	
	/**
	 * Constructor (the only acceptable way to set members of the class)
	 * 
	 * Local username will be the same as remoteUsername. 
	 * 
	 * @param hostname - host name of the remote host
	 * @param port - port on the remote host
	 * @param remoteusername - username to authenticate on the remote host
	 */
	public RshCredentials(String hostname, int port, String remoteUsername)
	{
		setCredentials(hostname, port, remoteUsername, remoteUsername);
	}
	
	/**
	 * Constructor (the only acceptable way to set members of the class)
	 * 
	 * Port will be set to the default value and the local username will be the same as remoteUsername. 
	 * 
	 * @param hostname - host name of the remote host
	 * @param remoteusername - username to authenticate on the remote host
	 */
	public RshCredentials(String hostname, String remoteUsername)
	{
		setCredentials(hostname, DEFAULT_RSH_PORT, remoteUsername, remoteUsername);
	}
	
	/*
	 * Utility function to set members of the class.
	 * It should be called by constructors only.
	 */
	private void setCredentials(String hostname, int port, String username, String localUsername)
	{
		this.hostname = hostname;
		this.port = port;
		this.username = username;
		this.localUsername = localUsername;
	}
	
	/**
	 * Returns the username onthe local host 
	 * (needed for hostbased rsh/rlogin authentication).
	 * 
	 * @return local username
	 */
	public String getLocalUsername()
	{
		return this.localUsername;
	}
}
