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

package com.jkovacic.cli;

import com.jkovacic.rclient.*;

/**
 * A class implementing remote command execution via Rsh (Rlogin).
 * This is a generic class, independent of the Rsh library used.
 * The actual instance of Rsh implementation is passed to the constructor.
 * 
 * Note that this method is considered insecure as the hostbased authentication
 * is easy to spoof and all data re transmitted unencrypted.
 * You are only recommended to use it in a well isolated local network or via an encrypted VPN.
 * 
 * Note that client connects from a port number between 512 and 1023. 
 * On Unix, root privileges are required. Additionally Java security policies
 * must be set to allow connections from this port range.
 * Additionally, rhosts file must be set appropriately on the remote host.
 * 
 * @author Jernej Kovacic
 */
public final class CliRsh extends CliAb 
{
	private Rsh remoteContext = null;
	
	/*
	 * Constructor, sets up the Rsh context variable
	 * 
	 * @param an instance of a rsh functionality implementing class
	 */
	CliRsh( Rsh ctxRsh )
	{
		this.remoteContext = ctxRsh;
	}
	
	/**
	 * Executes a command over rsh method 'exec'
	 * 
	 * @param processor - a class that will process the command's outputs
	 * @param command - full command to execute, given as one line
	 * 
	 * @return an instance of CliOutput with results of the executed command
	 * 
	 * @throws CliException when execution fails for any reason
	 */
	public CliOutput exec(ICliProcessor processor, String command) throws CliException 
	{
		// check input parameters:
		if ( null==command || 0==command.length() )
		{
			throw new CliException("No command to execute");
		}
		
		if ( null == remoteContext )
		{
			throw new CliException("No Rsh context provided");
		}
		
		CliOutput retVal = null;
		
		try
		{
			retVal = remoteContext.exec(processor, command);
		}
		catch ( RException ex )
		{
			throw new CliException("Rsh failed: " + ex.getMessage() );
		}
		
		return retVal;
	}

	/**
	 * Implementation of a method declared by IExec.
	 * Establishes a connection to a Rsh service.
	 * 
	 * @throws CliException if something fails
	 */
	public void prepare() throws CliException 
	{
		try
		{
			if ( null == remoteContext )
			{
				throw new CliException("No Rsh context provided");
			}
			else
			{
				remoteContext.connect();
			}
		}
		catch ( RException ex )
		{
			throw new CliException("Preparation of Rsh session failed: " + ex.getMessage() );
		}

	}

	/**
	 * Implementation of a method declared by IExec.
	 * Terminates the Rsh connection.
	 * 
	 * @throws CliException if something fails
	 */
	public void cleanup() throws CliException 
	{
		try
		{
			if ( null != remoteContext )
			{
				remoteContext.disconnect();
			}
		}
		catch ( RException ex )
		{
			throw new CliException("Cleanup of Rsh session failed: " + ex.getMessage() );
		}
	}

	/**
	 * Implementation of a method declared by IExec.
	 * 
	 * Returns information whether the session is active (connection is established)
	 * 
	 * @return true/false
	 */
	public boolean sessionActive() 
	{
		return ( null==remoteContext ? false : remoteContext.isConnected() );
	}
}
