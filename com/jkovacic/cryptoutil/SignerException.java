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

package com.jkovacic.cryptoutil;

/**
 * An exception, thrown at unexpected events during a digital signature process
 * 
 * @author Jernej Kovacic
 */
public class SignerException extends Exception 
{
	static final long serialVersionUID = 34567L;
	
	/**
	 * Constructor with a description
	 * 
	 * @param desc - description of the exception, later may be retrieved by getMessage 
	 */
    SignerException(String s)
    {
        super(s);
    }
}
