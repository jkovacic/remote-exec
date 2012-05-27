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
 * A base class with some common stuff for derived DER handling classes.
 * 
 * DER is an encoding scheme for the ASN.1 specification, it is available at:
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 * 
 * @author Jernej Kovacic
 * 
 * @see DerDecoder, DerEncoder
 */
abstract class DerAb 
{
	/**
	 * An exception used internally within this and derived classes.
	 * It must not be thrown by public methods.
	 * 
	 * @author Jernej Kovacic
	 */
	protected class DerException extends Exception
	{
		static final long serialVersionUID = 76341274L; 
		DerException(String desc)
		{
			super(desc);
		}
	}

	/**
	 * An enumerator with currently supported ASN.1 types and their numeric codes.
	 * It is possible to easily add more types if necessary.
	 * 
	 * @author Jernej Kovacic
	 */
	protected enum Asn1Types
	{
		SEQUENCE(0x30),
		INTEGER(0x02),
		BIT_STRING(0x03),
		OBJECT(0x06),
		OCTET_STRING(0x04),
		// EC key specific types:
		CONTAINER0(0xA0),
		CONTAINER1(0xA1);
		
		private int value;
		
		/*
		 * Constructor. Assigns a numeric value to a field
		 * 
		 * @param val - numeric value
		 */
		Asn1Types(int val)
		{
			this.value = val;
		}
		
		/**
		 * @return - field's numeric value as defined by the ASN.1 standard
		 */
		public int getValue()
		{
			return value;
		}
	}
}
