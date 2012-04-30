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

import java.io.*;

 /**
  * Implementation of ICliProcessor that handles non-interactive
  * command execution, i.e. stdin is ignored and the entire output
  * (from stdout and stderr) is packed into CliOutput. 
  * 
  * @author Jernej Kovacic
  */

public class CliNonInteractive implements ICliProcessor
{
	/**
	  Different operating systems use different system specific line separators,
	  e.g. "\n" in UNIX, "\r\n" in Windows, etc. To circumvent this problem, the constant EOL was introduced.
	  It is publicly available as a static member for other classes that might need it. 
	 */
	public static final String EOL = System.getProperty("line.separator");
	
	/**
	    * Reads commands output data (from stdout and stderr) and packs it into CliOutput in a friendlier form 
	    *
	    * @param stdinStream - OutputStream of stdin (ignored in this class, only declared because of the interface)
	    * @param stdoutStream - InputStream of stdout
	    * @param stderrStream - InputStream of stderr
	    * 
	    * @return an instance of CliOutput with processed results
	    * 
	    * @throws CliException when an error occurs
	    * 
	    * @see CliOutput, InputStream
	    */
	   public CliOutput process(OutputStream stdinStream, InputStream stdoutStream, InputStream stderrStream) throws CliException
	   {

		   // check of input parameters
		   if ( null==stdoutStream || null==stderrStream )
		   {
			   throw new CliException("Output streams not provided");
		   }
		   
			StringBuilder out = new StringBuilder("");
	        StringBuilder err = new StringBuilder("");
	        CliOutput retOutput = new CliOutput();
	        
	        BufferedReader stdout = new BufferedReader(new InputStreamReader(stdoutStream));
	        BufferedReader stderr = new BufferedReader(new InputStreamReader(stderrStream));
	        String outLine = null;
	        String errLine = null;
	        boolean firstOut = true;
	        boolean firstErr = true;
	   
	        // OS specific line separators will be inserted among returned lines from stdout or stderr. 
	        // At the end both strings will be split into arrays.
	        // Alternatively both inputs could be stored into ArrayLists...
	          
	        try
	        {
	        	// get input from any stream...
		        while ( (outLine = stdout.readLine()) != null || (errLine = stderr.readLine() ) != null ) 
		        {
		            if ( outLine != null )
		            {
		                if ( false == firstOut )
		                {
		                    out.append(EOL);
		                }
		                else
		                {
		                    firstOut = false;
		                }
		                out.append(outLine);
		            }
		            if ( errLine != null )
		            {
		                if ( false == firstErr )
		                {
		                    err.append(EOL);
		                }
		                else
		                {
		                    firstErr = false;
		                }
		                err.append(errLine);
		            }
		        }  // while
		
		        if ( null != out && out.length()>0 )
		        {
		        	retOutput.outStr = out.toString().split(EOL);
		        }
		        else
		        {
		        	retOutput.outStr = null;
		        }
		        
		        if ( null != err && err.length()>0 )
		        {
		        	retOutput.errStr = err.toString().split(EOL);
		        }
		        else
		        {
		        	retOutput.errStr = null;
		        }
	        }
	        catch ( IOException ex )
	        {
	        	throw new CliException("IO error while parsing stdout or stderr");
	        }
	        
	        return retOutput;
	   }
}
