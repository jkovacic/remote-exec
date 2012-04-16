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

/*
 * A class with some common elements for remote services authentication.
 * 
 * This class should never be declared by the application, 
 * always declare one of its derived classes.
 * 
 * @author Jernej Kovacic
 */
abstract class RCredentials 
{
	// A host to connect to 
	protected String hostname;
	
	// Port number of the r* daemon
	protected int port;
	
	// Username to authenticate on the remote host 
	protected String username;
	
	/**
	 * Returns the hostname of the remote server
	 * 
	 * @return hostname
	 */
	public String getHostname()
	{
		return hostname;
	}
	
	/**
	 * Returns the port of the remote server
	 * 
	 * @return port number
	 */
	public int getPort()
	{
		return port;
	}
	
	/**
	 * Returns the username to authenticate on the remote server
	 * 
	 * @return username on the remote server
	 */
	public String getUsername()
	{
		return username;
	}
}
