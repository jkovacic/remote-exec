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

import com.jkovacic.cli.*;

import java.io.*;
import org.apache.commons.net.bsd.*;

/**
 * Actual implementation of rexec functionality, based on an open source 
 * (Apache licence) Apache Commons Net library, available at:
 * http://commons.apache.org/net/
 * This implementation is based on the version 3.1.
 * 
 * Note: the library does not support obtaining remote process's
 * exit code, so it is always set to CliOutput.EXITCODE_NOT_SET
 * 
 * @author Jernej Kovacic
 */
public final class RexecApache extends Rexec 
{
	private RExecClient rexecContext = null;

	/*
	 * Constructor, should only be called by a factory
	 */
	RexecApache(RexecCredentials cred)
	{
		super(cred);
	}
	
	/*
	 * Utility function to terminate the connection (if necessary)
	 * and dispose the instance of the Apache library class.
	 */
	private void cleanup()
	{
		if ( null != rexecContext )
		{
			if ( true == rexecContext.isConnected() )
			{
				try
				{
					rexecContext.disconnect();
				}
				catch ( IOException ex )
				{
					// not much to do, even if disconnection has failed 
				}
			}
			
			rexecContext = null;
		}
	}
	
	/**
	 * Establishes a connection to a r* daemon
	 * 
	 * @throws RException if it fails
	 */
	public void connect() throws RException 
	{
		// connection will only be established if it does not exist yet
		if ( null != rexecContext )
		{
			return;
		}

		// check of credential validity
		if ( null == cred )
		{
			throw new RException("No credentials provided");
		}
		
		// TODO further checking of credentials?
		
		try
		{
			rexecContext = new RExecClient();
			// TODO use isAvailable()?
			rexecContext.connect(cred.getHostname(), cred.getPort() );
		}
		catch ( IOException ex )
		{
			cleanup();
			throw new RException("Connection to rexec service failed");
		}
	}

	/**
	 * Terminates the connection to the r* daemon
	 * 
	 * @throws RException if it fails
	 */
	public void disconnect() throws RException 
	{
		cleanup();
	}

	/**
	 * Executes a remote command over the r* daemon
	 * 
	 * @param processor - a class that will process the command's outputs
	 * @param command to be executed remotely
	 * 
	 * @return output of the command
	 * 
	 * @throws RException if it fails
	 */
	public CliOutput exec(ICliProcessor processor, String command) throws RException 
	{
		CliOutput retVal = null;
		
		// check of input parameters
		if ( null==command || 0==command.length() )
		{
			throw new RException("Nothing to execute");
		}
		
		// is connection established?
		if ( null == rexecContext )
		{
			throw new RException("Connection to rexec service not established");
		}
		
		// connection is established, try to exec the command remotely
		try
		{
			rexecContext.rexec(cred.getUsername(), 
					String.copyValueOf(cred.getPassword()), 
					command, 
					true);
		}
		catch ( IOException ex )
		{
			throw new RException("Command execution failed");
		}
		
		// ... and process its output
		try
		{
			retVal = processor.process(rexecContext.getOutputStream(), rexecContext.getInputStream(), rexecContext.getErrorStream() );
		}
		catch ( CliException ex )
		{
			throw new RException("Could not process output streams");
		}
		
		// processor.process returns when the remote process is terminated
		
		// The library does not support exit code
		retVal.exitCode = CliOutput.EXITCODE_NOT_SET;
		
		return retVal;
	}
	
	/**
	 * Is the connection to the remote daemon established?
	 * 
	 * @return true/false
	 */
	public boolean isConnected()
	{
		boolean retVal = false;
		
		// if an instance of Apache library's class is present,
		// use its method isConnected, otherwise false will be returned.
		if ( null != rexecContext )
		{
			retVal = rexecContext.isConnected();
		}
		
		return retVal;
	}

}
