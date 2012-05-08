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
 * Interface with declaration of methods that must be implemented by
 * CLI processing classes. Specialized classes can implement this interface,
 * performing additional filtering of the output, interactive managing
 * of the remote process, etc.
 * 
 * @author Jernej Kovacic
 */
public interface ICliProcessor 
{
	/**
	 * Processes the command's outputs (of stdoutStream and StderrStream).
	 * Depending on implementation it is possible to influence the command
	 * by writing to stdinStream. 
	 * 
	 * When the command execution is finished, probably all implementations 
	 * will assign the command's exit code to the CliOutput.exitCode.
	 * It is expected that command's outputs will be assigned (line by line)
	 * to CliOutput.outStr and CliOutput.errStr. 
	 * Of course, this depends on the implementation.
	 * 
	 * @param stdinStream - a stream to send input data to the command's stdin
	 * @param stdoutStream - a stream to read the commands stdout
	 * @param stderrStream - a stream to read the command's stderr
	 * 
	 * @return instance of CliOutput, containing exit code with results of stdout and stderr
	 * 
	 * @throws CliException if something fails
	 */
	public CliOutput process(OutputStream stdinStream, InputStream stdoutStream, InputStream stderrStream) throws CliException;
}
