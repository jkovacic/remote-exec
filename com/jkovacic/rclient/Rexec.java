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
 * An abstract class for rexec functionality.
 * 
 * Typically, in an application this class should be declared
 * and a derived class (with actual implementation) should actually be instantiated.
 * 
 * @author Jernej Kovacic
 * 
 * @see RexecApache
 */
public abstract class Rexec implements Rclient
{
	protected RexecCredentials cred;
	
	/*
	 * Constuctor, called by derived classes.
	 * 
	 * Assigns a specialized class with all credentials 
	 * required for a successful connection.
	 */
	protected Rexec(RexecCredentials cred)
	{
		this.cred = cred;
	}
	
	/**
	 * Is the connection to the remote daemon established?
	 * 
	 * @return true/false
	 */
	public abstract boolean isConnected();
}
