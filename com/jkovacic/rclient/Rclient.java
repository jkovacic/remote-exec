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

/**
 * An interface with declared common methods for r* services (rsh, rexec)
 * 
 * @author Jernej Kovacic
 */
public interface Rclient 
{

	/**
	 * Establishes a connection to a r* daemon
	 * 
	 * @throws RException if it fails
	 */
	public abstract void connect() throws RException;
	
	/**
	 * Terminates the connection to the r* daemon
	 * 
	 * @throws RException if it fails
	 */
	public abstract void disconnect() throws RException;
	
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
	public abstract CliOutput exec(ICliProcessor processor, String command) throws RException;
}
