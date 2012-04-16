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

import com.jkovacic.ssh2.*;

/**
 * A class implementing remote command execution via SSH.
 * This is a generic class, independent of the SSH library used.
 * The actual instance of SSH implementation is passed to the constructor.
 * 
 * @author Jernej Kovacic
 */
public final class CliSsh extends CliAb
{
	private Ssh2 sshcontext = null;
	
	/*
	 * Constructor, sets up the SSH context variable
	 * 
	 * @param an instance of a SSH functionality implementing class
	 */
	CliSsh( Ssh2 sshContext )
	{
		this.sshcontext = sshContext;
	}
	
	/**
	 * Executes a command over SSH 'exec'
	 * 
	 * @param command - full command to execute, given as one line
	 * 
	 * @return an instance of CliOutput with results of the executed command
	 * 
	 * @throws CliException when execution fails for any reason
	 */
	public CliOutput exec(String command) throws CliException
	{
		// check input parameters:
		if ( null==command || 0==command.length() )
		{
			throw new CliException("No command to execute");
		}
		
		if ( null == sshcontext )
		{
			throw new CliException("No SSH context provided");
		}
		
		CliOutput retVal = null;
		
		try
		{
			retVal = sshcontext.exec(command);
		}
		catch ( SshException ex )
		{
			throw new CliException("SSH exec failed: " + ex.getMessage() );
		}
		
		return retVal;
	}
	
	/**
	 * Implementation of a method declared by IExec.
	 * Establishes a connection to a SSH server.
	 * 
	 * @throws CliException if something fails
	 */
	public void prepare() throws CliException
	{
		try
		{
			if ( null == sshcontext )
			{
				throw new CliException("No SSH context provided");
			}
			else
			{
				sshcontext.connect();
			}
		}
		catch ( SshException ex )
		{
			throw new CliException("Preparation of SSH session failed: " + ex.getMessage() );
		}
	}
	
	/**
	 * Implementation of a method declared by IExec.
	 * Terminates the SSH connection.
	 * 
	 * @throws CliException if something fails
	 */
	public void cleanup() throws CliException
	{
		try
		{
			if ( null != sshcontext )
			{
				sshcontext.disconnect();
			}
		}
		catch ( SshException ex )
		{
			throw new CliException("Cleanup of SSH session failed: " + ex.getMessage() );
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
		return ( null==sshcontext ? false : sshcontext.isConnected() );
	}

}
