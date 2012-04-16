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
 * This factory class is intended to be the only "legal" way
 * to create instances derived from Rclient (various classes with rexec or rsh functionality) 
 * 
 * Methods are static so no instantiation is necessary 
 * 
 * @author Jernej Kovacic
 */
public class RFactory 
{
	/**
	 * Instantiates an instance of RexecApache, a 'rexec' implementation
	 * based on the 3rd party library Apache Commons Net.
	 * 
	 * @param cred - credentials necessary to authenticate on a remote server
	 * 
	 * @return an instance of RexecApache
	 * 
	 * @throws RException if credentials are missing
	 */
	public static RexecApache getApacheRexecInstance(RexecCredentials cred) throws RException
	{
		// check of input parameters
		if ( null == cred )
		{
			throw new RException("Credentials not provided");
		}
				
		if ( null==cred.getHostname() || 0==cred.getHostname().length() )
		{
			throw new RException("Invalid host name");
		}
		
		if ( null==cred.getUsername() || 0==cred.getUsername().length() )
		{
			throw new RException("Invalid username");
		}
		
		// Empty passwords are allowed (if not recommended)
		
		return new RexecApache(cred);
	}
	
	/**
	 * Instantiates an instance of RshcApache, a 'rsh' implementation
	 * based on the 3rd party library Apache Commons Net.
	 * 
	 * @param cred - credentials necessary to authenticate on a remote server
	 * @return an instance of RshApache
	 * @throws RException - if credentials are missing
	 */
	public static RshApache getApacheRshInstance(RshCredentials cred) throws RException
	{
		// check of input parameters
		if ( null == cred )
		{
			throw new RException("Credentials not provided");
		}
				
		if ( null==cred.getHostname() || 0==cred.getHostname().length() )
		{
			throw new RException("Invalid host name");
		}
		
		if ( null==cred.getUsername() || 0==cred.getUsername().length() )
		{
			throw new RException("Invalid remote username");
		}
		
		if ( null==cred.localUsername || 0==cred.localUsername.length() )
		{
			throw new RException("Invalid local username");
		}
		
		return new RshApache(cred);
	}
}
