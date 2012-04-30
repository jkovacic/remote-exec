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
* This class just groups results of the executed command, i.e. the exit code and outputs from stdout and stderr.
* To most parsers, the most convenient form of both outputs are string arrays of lines.
* Exit code is dependent of the external program, by convention  0 is returned on success, any other integer on failure.
* Consult command's man page for more details.
*
* Typically all three properties are needed by the calling methods immediately after the external command is executed.
* Hence there is no need to hide the properties and all three are public. Get-methods are also available but are actually redundant.
* 
* Note: one should not rely on determining of the command's success from the exit code. It is not supported
* by all CLI implementations. In such a case, EXITCODE_NOT_SET is set.
* It is a much better idea to process returned output streams and make any conclusions on their basis. 
* 
* @author Jernej Kovacic
*/

public class CliOutput
{
	/**
	 * Not all CLI implementations support fetching of command's exit code. 
	 * In such cases this value is set. This is the lowest possible int value.
	 * It is very unlikely that any process would ever set it as its exit code.
	 */
	public static final int EXITCODE_NOT_SET = Integer.MIN_VALUE; 
	
	/**
	 The exit code after the command has finished. By convention it is set to 0 on success.
	*/
	public int exitCode;
	
	/**
	 Array of lines returned by stdout. Note that it may be empty. 
	*/
    public String[] outStr;
    
    /**
     Array of lines returned by stderr. Note that it may be empty.
    */
    public String[] errStr;
    
    /**
     Constructor
    */
    public CliOutput()
    {
        outStr = null;
        errStr = null;
        exitCode = -1;
    }

    /**
     * A convenience function to determine whether the 
     * remote process's exit code was set.
     * 
     * @return true/false
     */
    public boolean isExitCodeSet()
    {
    	return ( EXITCODE_NOT_SET != exitCode );
    }
    
    /**
     @return value of exitCode
    */
    public int getExitCode()
    {
        return exitCode;
    }

    /**
     @return reference to outStr 
    */
    public String[] getOut()
    {
        return outStr;
    }

    /** 
     @return reference to errStr
    */
    public String[] getErr()
    {
        return errStr;
    }

}
