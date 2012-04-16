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

/**
 * An interface whose primary task is to "mark" all Enums with various families
 * encryption algorithms. It does not only "glue" the related Enums but also helps
 * automation of some tasks common to all of these Enums.
 * 
 * Note that each derived class must also implement getAlg as a static method which
 * Java prohibits to declare in interfaces. 
 * 
 * @author Jernej Kovacic
 *
 * @see Ciphers, Hmacs, KexAlgs, CompAlgs, PKAlgs
 */
public interface ISshEncryptionAlgorithmFamily 
{
	/**
	 * Returns the name of the algorithm as defined by SSH2 handshaking and key exchange protocols
	 * 
	 * @return name of the algorithm as a string
	 */
	public String getName();
	
	/*
	 getAlg (inverse of getName) could also be declared here but it can only be implemented
	 as a static method which are not allowed in interfaces.
	 */
}
