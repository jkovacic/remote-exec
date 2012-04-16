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

package com.jkovacic.ssh2;

import com.jkovacic.cryptoutil.*;

/**
 * An interface indicating it is possible to convert (also called "marshal" in SOAP)
 * an instance implementing this interface to an instance implementing
 * IEncryptionFamily in the package com.jkovacic.cryptoutil.
 * 
 * This interface was introduced to facilitate (using generic programming) 
 * conversion to implementations of IEncryptionFamily.
 * 
 * @author Jernej Kovacic
 * 
 * @see com.jkovacic.cryptoutil.IEncryptionFamily
 */
public interface ISshMarshalledAlgorithm 
{
	/**
	 * Convert (if possible) into an instance of IEncryptionFamily
	 * (declared in com.jkovacic.cryptoutil, hence the name)
	 * 
	 * @return instance of IEncryptionFamily if conversion is possible, null if not
	 */
	public IEncryptionAlgorithmFamily toCU();
	
	/*
	 fromCU (inverse of toCU) could also be declared here but it can only be implemented
	 as a static method which are not allowed in interfaces.
	*/

}
