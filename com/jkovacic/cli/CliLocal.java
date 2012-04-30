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
CliLocal executes external commands or programs and returns resulting output.

@author Jernej Kovacic
@see si.jkovacic.CliOutput
*/

public final class CliLocal extends CliAb 
{

	/*
	    The only acceptable way to instantiate all implementations of IExec
	    is via factories, hence the constructor is private
	*/
	private CliLocal()
	{
		// nothing to initialize, empty constructor
	}
	
	/**
    Executes the command, given as a string. No environment parameters are passed to the external command.
    Hence the entire path to the external program must be given. 
    
    @param processor - a class that will process the command's outputs
    @param command, e.g. "/bin/iostat -En c0t2d0"
    
    @return instance of CliOutput, containing exit code with results of stdout and stderr
    
    @throws CliException if an error occurs while trying to execute the "command"
  */

	public CliOutput exec(ICliProcessor processor, String command) throws CliException 
	{        
 
		CliOutput retVal = null;
		
        if ( null == command || 0 == command.length() )
        {
        	// Nothing to execute, this is unexpected.
        	throw new CliException("Nothing to execute");
        }
        
        try
        {
        	// Typical implementation for local execution of CLI commands
            Runtime rt = Runtime.getRuntime();
            Process pr = rt.exec(command);
            
            // process outputs by the universal processing method
            retVal = processor.process(pr.getOutputStream(), pr.getInputStream(), pr.getErrorStream());
            // and assign the exit code
            retVal.exitCode = pr.waitFor();      
        }
        catch (Exception ex)
        {
        	// TODO handle
            throw new CliException(ex.getMessage());
        }
        return retVal;

	}

	/**
	 * This method does not make sense at local CLI environments,
	 * it is "implemented" as an empty block. 
	 * 
	 * @throws CliException (never thrown)
	 */
	public void prepare() throws CliException
	{
		
	}
	
	/**
	 * This method does not make sense at local CLI environments,
	 * it is "implemented" as an empty block. 
	 * 
	 * @throws CliException (never thrown)
	 */
	public void cleanup() throws CliException
	{
		
	}
	
	/**
	 * This method does not make sense at local CLI environments,
	 * so it always returns true.
	 * 
	 * @return true
	 */
	public boolean sessionActive()
	{
		return true;
	}
	
	/*
	 A factory to instantiate an object of this class 
	 
	 @param none
	 @return an instance of CliLocal
	*/
	static CliLocal getInstance()
	{
		return new CliLocal();
	}
	
}
