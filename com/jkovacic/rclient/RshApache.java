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

import java.io.IOException;

import org.apache.commons.net.bsd.*;
import com.jkovacic.cli.*;

/**
 * Actual implementation of remote execution via rsh/rlogin, based on an open source 
 * (Apache licence) Apache Commons Net library, available at:
 * http://commons.apache.org/net/
 * This implementation is based on the version 3.1.
 * 
 * @author Jernej Kovacic
 */
public final class RshApache extends Rsh 
{
	private RCommandClient rshContext = null;
	
	/*
	 * Constructor, should only be called by a factory
	 */
	RshApache(RshCredentials cred)
	{
		super(cred);
	}
	
	/*
	 * Utility function to terminate the connection (if necessary)
	 * and dispose the instance of the Apache library class.
	 */
	private void cleanup()
	{
		if ( null != rshContext )
		{
			if ( true == rshContext.isConnected() )
			{
				try
				{
					rshContext.disconnect();
				}
				catch ( IOException ex )
				{
					// not much to do, even if disconnection has failed 
				}
			}
			
			rshContext = null;
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
		if ( null != rshContext )
		{
			return;
		}

		// Check of credential validity
		if ( null == cred )
		{
			throw new RException("No credentials provided");
		}
		
		// TODO further checking of credentials?
		
		try
		{
			rshContext = new RCommandClient();
			// TODO use isAvailable()?
			rshContext.connect(cred.getHostname(), cred.getPort() );
		}
		catch ( IOException ex )
		{
			cleanup();
			throw new RException("Connection to rsh service failed");
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
		if ( null == rshContext )
		{
			throw new RException("Connection to rexec service not established");
		}
		
		// connection is established, try to exec the command remotely
		try
		{
			rshContext.rexec(cred.getUsername(), cred.getLocalUsername(), command, true);
		}
		catch ( IOException ex )
		{
			throw new RException("Command execution failed");
		}
		
		// ... and process its output
		try
		{
			retVal = processor.process(rshContext.getOutputStream(), rshContext.getInputStream(), rshContext.getErrorStream() );
		}
		catch ( CliException ex )
		{
			throw new RException("Could not process output streams");
		}
		
		// processOutputStreams returns when the remote process is terminated
		
		
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
		if ( null != rshContext )
		{
			retVal = rshContext.isConnected();
		}
		
		return retVal;
	}

}
