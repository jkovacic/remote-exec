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

package com.jkovacic.ssh2;

import java.util.*;

/**
 * Collection of data that uniquely identify a SSH server (host name, port, host keys)
 * 
 * @author Jernej Kovacic
 *
 */
public class HostId 
{
	private final int DEFAULT_SSH_PORT = 22;  // default port for SSH connections
	
	/** Host name (may be an IPv4 address, IPv6 address or or a DNS/hosts resolvable name)*/
	public String hostname;
	
	/** Server's SSH port (default is 22) */
	public int port = DEFAULT_SSH_PORT;
	
	/** List of server's host keys (server may have several host keys) */
	public List<Hostkey> hostkeys = null;
	
	/**
	 * Constructor
	 */
	public HostId()
	{
		this.hostname = null;
		this.port = DEFAULT_SSH_PORT;
		this.hostkeys = new LinkedList<Hostkey>();
	}
	
	/**
	 * Constructor that sets the host name
	 * 
	 * @param hostname - host address (an IPv4 address, an IPv6 address or or a DNS/hosts resolvable name)
	 */
	public HostId(String hostname)
	{
		this.hostname = hostname;
		this.hostkeys = new LinkedList<Hostkey>();
	}
	
	/**
	 * Inserts a host public key into the list of host keys. Only one "representative"
	 * of each supported public key algorithms can be inserted
	 * 
	 * @param hostkey - a host key to be inserted
	 * 
	 * @throws SshException when inappropriate keys are attempted to be inserted
	 */
	public void insertHostkey(Hostkey hostkey) throws SshException
	{
		// Should never happen, check just in case
		if ( null == this.hostkeys )
		{
			throw new SshException("List of host keys not initialized");
		}
		
		// is the actual host key provided?
		if ( null == hostkey )
		{
			throw new SshException("Host key not specified");
		}
		
		// does it have the PK method set?
		PKAlgs method = hostkey.getMethod();
		if ( null == method )
		{
			throw new SshException("Host key methods not specified");
		}
		
		// OK, input data are finally verified, now let us finally check
		// if a key with the same method already is in the list
		
		for ( Hostkey tempkey : hostkeys )
		{
			
			if ( method.equals(tempkey.getMethod()) )
			{
				throw new SshException("Method '" + method + "' already used among valid hostkeys");
			}
		}
		
		// If this point is reached, the method is unique, apply the host key
		hostkeys.add(hostkey);		
	}
}
