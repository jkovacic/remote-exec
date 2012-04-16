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
import com.jkovacic.rclient.*;

/**
 * This factory class is intended to be the only "legal" way
 * to create instances of IExec (various classes with CLI functionality) 
 * 
 * Methods are static so no instantiation is necessary 
 * 
 * @author Jernej Kovacic
 */

// At the moment it supports only local, SSH and r-services based execution.
// In future it may be extended to support RMI, CORBA, etc. as well

public class CliFactory 
{
	/**
	 * Instantiates a class with local CLI functionality
	 * 
	 * @return an instance of the class CliLocal
	 * 
	 * @see CliLocal
	 */
	public static CliLocal getLocal()
	{
		return CliLocal.getInstance();
	}
	
	/**
	 * Instantiates one of implemented classes with SSH exec functionality.
	 * 
	 * At the moment there is only one implementation available, based
	 * on the library Ganymed SSH2.
	 * 
	 * @param which - an Enum indicating the actual implementation of SSH2 functionality
	 * @param host - a class with data of the SH server to connect to
	 * @param user - a class with user credentials for authentication to the SSH server
	 * @param algs - a class with preferred encryption algorithms
	 * 
	 * @return an instance of a class with SSH exec functionality
	 * 
	 * @throws CliException when missing SSH parameters
	 * 
	 * @see SshGanymed
	 */
	public static CliSsh getSsh(Ssh2.SshImpl which, HostId host, UserCredentials user, EncryptionAlgorithms algs) throws CliException
	{		
		CliSsh retVal = null;
		Ssh2 ssh = null;	// instance of a class, derived from Ssh2
		
		// check of input parameters
		if ( null==host || null==user || null==algs )
		{
			throw new CliException("Not all SSH parameters provided");
		}
		
		try
		{
			if ( null != which )
			{
				switch (which)
				{
				case GANYMED:
					ssh= SshFactory.getGanymedInstance(host, user, algs);
					break;
					
				case JSCH:
					ssh = SshFactory.getJschInstance(host, user, algs);
					break;
					
				default: 
					// implementations with other SSH libraries currently not implemented
					ssh = null;
				}
			

				// if a SSH class has been instantiated, use it
				// to construct an instance of CliSsh
				if ( null == ssh )
				{
					throw new CliException("No SSH context could be instantiated");
				}
			
				retVal = new CliSsh(ssh);
			}  // if which!=null
		}  // try
		catch ( SshException ex )
		{
			throw new CliException("SshException caught: '" + ex.getMessage() + "'");
		}
		
		return retVal;
	}
	
	/**
	 * A factory method to instantiate a class with SSH exec functionality
	 * 
	 * @param sshContext - a class with implemented SSH functionality
	 * 
	 * @return an instance of CliSsh
	 * 
	 * @throws CliException if no sshContext is provided
	 */
	public static CliSsh getSsh( Ssh2 sshContext ) throws CliException
	{
		// check of input parameters
		if ( null == sshContext )
		{
			throw new CliException("No SSH context provided");
		}
		
		return new CliSsh(sshContext);
	}
	
	/**
	 * Instantiates a class with implemented Rexec functionality.
	 * 
	 * At the moment there is only one implementation available, based
	 * on the library Apache Commons library.
	 * 
	 * @param credentials - A class with necessary credentials 
	 * 
	 * @return an instance of a class with Rexec functionality
	 * 
	 * @throws CliException when missing credentials
	 * 
	 * @see RexecCredentials, Rexec, RexecApache
	 */
	public static CliRexec getRexec(RexecCredentials credentials) throws CliException
	{
		// check of input parameters
		if ( null == credentials )
		{
			throw new CliException("No credentials provided");
		}
		
		Rexec ctxRexec = null;
		CliRexec retVal = null;
		
		try
		{
			ctxRexec = RFactory.getApacheRexecInstance(credentials);
			retVal = new CliRexec(ctxRexec);
		}
		catch ( RException ex )
		{
			throw new CliException("RException caught: '" + ex.getMessage() + "'");
		}
		
		return retVal;
	}
	
	/**
	 * Instantiates a class with implemented Rsh (rlogin) exec functionality.
	 * 
	 * At the moment there is only one implementation available, based
	 * on the library Apache Commons library.
	 * 
	 * @param credentials - A class with necessary credentials 
	 * 
	 * @return an instance of a class with Rsh functionality
	 * 
	 * @throws CliException when missing credentials
	 * 
	 * @see RshCredentials, Rsh, RshApache
	 */
	public static CliRsh getRsh(RshCredentials credentials) throws CliException
	{
		// check of input parameters
		if ( null == credentials )
		{
			throw new CliException("No credentials provided");
		}
		
		Rsh ctxRsh = null;
		CliRsh retVal = null;
		
		try
		{
			ctxRsh = RFactory.getApacheRshInstance(credentials);
			retVal = new CliRsh(ctxRsh);
		}
		catch ( RException ex )
		{
			throw new CliException("RException caught: '" + ex.getMessage() + "'");
		}
		
		return retVal;
	}
	
}
