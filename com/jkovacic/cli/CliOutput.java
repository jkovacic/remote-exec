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
* Hence there is no need to hide the properties and all three are public.  Get-methods are also available but are actually redundant.  
* 
* @author Jernej Kovacic
*/

public class CliOutput
{
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
