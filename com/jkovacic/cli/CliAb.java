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
 * An abstract class with implemented methods, common to all implementations of IExec.
 * 
 * @author Jernej Kovacic
 *
 */

abstract class CliAb implements IExec 
{
	/*
	 * Probably CliNonInteractive will be used very often to process command's
	 * output streams. Hence, an instance is created to be passed to exec's with
	 * no ICliProcessor given. CliNonInteractive is not stateful and could well be
	 * static if inheritance rules allowed it. This means, one instance of this class
	 * is sufficient for unlimited number of processings, so the member is static 
	 */
	protected static CliNonInteractive noninteractiveCtx = new CliNonInteractive();
	
	/**
	 * Executes a command and processes its output using CliNonInteractive
	 * 
	 * @param command - a command to be executed
	 * 
	 * @return instance of CliOutput, containing exit code with results of stdout and stderr
	 * 
	 * @throws CliException when anything fails
	 */
	public CliOutput exec(String command) throws CliException
	{
		return exec(noninteractiveCtx, command);
	}
	
	/**
    * Another commonly used method of passing the external command and its parameters is in a form of an array of strings.
    * The array can be null terminated, if not all n elements (n equal to its full size) will be taken.
    * This method converts the array into a single command line and executes it.   
    * No environment parameters are passed to the external command.
    * Hence the entire path to the external program must be given in the first parameter.
    * Spaces are automatically inserted among parameters.
    *
    * @param processor - class that will process the command's outputs
    * @param commands - array of a command and parameters, e.g. {"/bin/iostat", "-En", "c0t2d0", null}
    *
    * @return instance of CliOutput, containing exit code with results of stdout and stderr
    *
    * @throws CliException if an error occurs while trying to execute the command
   */
   public CliOutput exec(ICliProcessor processor, String[] commands) throws CliException
   {
   	// join all array members (actually all till the first occurrence of null) into a string and call runCommand(string)
   	StringBuilder cmd = new StringBuilder("");
   	
   	if ( null == commands )
   	{
   		// Nothing to execute, this is unexpected.
   		throw new CliException("Nothing to execute");
   	}
   	
   	boolean first = true; // to determine whether a space must be prepended
   	for ( String comm : commands )
   	{
   		if ( false == first )
   		{
   			cmd.append(' ');
   		}
   		if ( null != comm )
   		{
   			cmd.append(comm);
   		}
   		else
   		{
   			break;  // out of for comm
   		}
   		
   		// at least one command passed the for loop, 
   		//the next one will definitely not be the 'first' anymore:
   		first = false;
   	}  // for comm
   	
   	if ( 0 == cmd.length() )
   	{
   		// empty "command" to execute, obviously something is wrong with input parameters
   		throw new CliException("Invalid CLI array");
   	}
   	
   	return exec(processor, cmd.toString());
   }
   
   /**
    * Runs exec(commands) (see this method for more info) and process the
    * command's outputs using CliNonInteractive.
    * 
    * @param commands - a null terminated array of commands and parameters to be executed
    * 
    * @return instance of CliOutput, containing exit code with results of stdout and stderr
    * 
    * @throws CliException when anything fails
    */
   public CliOutput exec(String[] commands) throws CliException
   {
	   return exec(noninteractiveCtx, commands);
   }
}
