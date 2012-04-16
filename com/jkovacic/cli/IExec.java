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

/**
 * An interface that all CLI execution classes must implement.
 * 
 * In cases of remote CLI execution (e.g. via SSH) it often does not make sense
 * to establish and interrupt a connection for each command (PK cryptography, used
 * during SSH key exchange and possibly user authentication, is CPU resources expensive!).
 * For that reason three methods have been declared:
 * prepare, sessionActive and cleanup. 
 * 
 * The current implementation is suitable for execution of commands where it is
 * feasible to control the command with its input parameters only (known before 
 * its execution) and where there is no need to control it via command's stdin and/or 
 * control it depending on stdout and/or stderr. 
 * 
 * @author Jernej Kovacic
 *
 * @see CliOutput, CliLocal, Ssh2, CliRexec, CliRsh
 */
public interface IExec 
{
	/**
	 * Exec a command
	 * 
	 * @param command - full command to execute, given as one line
	 * 
	 * @return an instance of CliOutput with results of the executed command
	 * 
	 * @throws CliException when execution fails for any reason
	 */
	public CliOutput exec(String command) throws CliException;
	
	/**
	 * Exec a command given as an array of parameters. Spaces will be inserted automatically.
	 * 
	 * @param commands - an array of a command and its parameters. Only parameters till the first occurrence of 'null' are passed.
	 * 
	 * @return an instance of CliOutput with results of the executed command
	 * 
	 * @throws CliException when execution fails for any reason
	 */
	public CliOutput exec(String[] commands) throws CliException;
	
	/**
	 * Prepares the CLI environment where applicable, e.g. establish a SSH connection, etc.
	 * Typically it is called before the first exec is performed.
	 * 
	 * @throws CliException
	 */
	public void prepare() throws CliException;
	
	/**
	 * Cleans up the CLI environment where applicable, e.g. disconnects a SSH connection, etc.
	 * Typically it is called after all execs have been performed. 
	 * 
	 * @throws CliException
	 */
	public void cleanup() throws CliException;
	
	/**
	 * Where applicable, checks whether the CLI environment is still active, e.g.
	 * if a SSH connection has not been interrupted.
	 * 
	 * @return true/false
	 */
	public boolean sessionActive();
}
