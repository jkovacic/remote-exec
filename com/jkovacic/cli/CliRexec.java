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
 * A class implementing remote command execution via Rexec.
 * This is a generic class, independent of the Rexec library used.
 * The actual instance of Rexec implementation is passed to the constructor.
 * 
 * Note that rexec is not considered secure as the password is transmitted unencrypted.
 * You are only recommended to use it in a local network or via an encrypted VPN.
 *  
 * @author Jernej Kovacic
 */
public final class CliRexec extends CliAb 
{

	private Rexec remoteContext = null;
	
	/*
	 * Constructor, sets up the Rexec context variable
	 * 
	 * @param an instance of a rexec functionality implementing class
	 */
	CliRexec( Rexec ctxRexec )
	{
		this.remoteContext = ctxRexec;
	}
	
	/**
	 * Executes a command over rexec method 'exec'
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
			throw new CliException("No Rexec context provided");
		}
		
		CliOutput retVal = null;
		
		try
		{
			retVal = remoteContext.exec(processor, command);
		}
		catch ( RException ex )
		{
			throw new CliException("Rexec failed: " + ex.getMessage() );
		}
		
		return retVal;
	}

	/**
	 * Implementation of a method declared by IExec.
	 * Establishes a connection to a Rexec service.
	 * 
	 * @throws CliException if something fails
	 */
	public void prepare() throws CliException 
	{
		try
		{
			if ( null == remoteContext )
			{
				throw new CliException("No Rexec context provided");
			}
			else
			{
				remoteContext.connect();
			}
		}
		catch ( RException ex )
		{
			throw new CliException("Preparation of Rexec session failed: " + ex.getMessage() );
		}

	}

	/**
	 * Implementation of a method declared by IExec.
	 * Terminates the Rexec connection.
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
			throw new CliException("Cleanup of Rexec session failed: " + ex.getMessage() );
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
