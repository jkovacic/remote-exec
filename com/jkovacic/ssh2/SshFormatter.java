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

import java.util.*;

/**
 * A convenience class that accepts various vectors and converts them
 * into the SSH defined format. Among others, this class is suitable 
 * to generate OpenSSH formatted public keys.
 * 
 * OpenSSH public key file format is defined in RFC 4716:
 * http://tools.ietf.org/html/rfc4716
 * SSH types (most interesting to us are string, mpint) are defined in RFC 4251, section 5:
 * http://tools.ietf.org/html/rfc4251#section-5
 * 
 * Typical format of each vector is composed by a four byte length (in octets, i.e bytes),
 * immediately followed by the bytes.
 * 
 * Typical usage of the class:
 * - instantiate the class with no parameters
 * - add vectors to be converted by calling add(). Strings and vectors of bytes and chars are currently accepted
 * - when all desired vectors have been added, call format() that returns the appropriate array of bytes. Order of vectors is preserved.
 * 
 * It is not possible to remove vectors from the object, however, even after calling 
 * format() it is possible to add additional vectors and call format() again,
 * taking effect on all added vectors, the previous ones and the newly added ones.
 * 
 * @author Jernej Kovacic
 */
public class SshFormatter 
{
	// list of vectors to be included into the final output
	private List<byte[]> vectors;
	
	/**
	 * Constructor
	 */
	public SshFormatter()
	{
		this.vectors = new ArrayList<byte[]>();
	}
	
	/**
	 * Adds an array of bytes to the list of vectors to be formatted.
	 * 
	 * @param vector - array of bytes
	 */
	public void add(byte[] vector)
	{
		if ( null!=vector )
		{
			vectors.add(vector);
		}
	}
	
	/**
	 * Adds an array of bytes to the list of vectors to be formatted.
	 * The characters will be converted into bytes.
	 * 
	 * @param vector - array of chars
	 */
	public void add(char[] vector)
	{
		if ( null!=vector )
		{
			// allocate an array of bytes...
			byte[] b = new byte[vector.length];
			// ...and convert each char into a byte
			for ( int i=0; i<vector.length; i++ )
			{
				b[i] = (byte) vector[i];
			}
			// finally add the array of bytes to the list
			add(b);
		}
	}
	
	/**
	 * Adds characters of a string to the list of vectors to be formatted.
	 * String's characters will be converted to bytes.
	 * 
	 * @param str - string
	 */
	public void add(String str)
	{
		if ( null!=str )
		{
			// "convert" the string into an array of chars
			char[] c = str.toCharArray();
			// add the vector of chars to the list
			add(c);
			// the chars are not needed anymore, so zero them out
			Arrays.fill(c, '\u0000');
		}
	}
	
	/*
	 * A utility function that converts an integer value into an array of four bytes.
	 * 
	 * @param a - integer value to be converted
	 * 
	 * @return a four byte array of bytes representing the given integer value
	 */
	private byte[] intToBytes(int a)
	{
		byte[] retVal = new byte[4];
		int l = a;
		
		Arrays.fill(retVal, (byte) 0);
		
		// using bitwise operators extract the least significant byte from the integer value,
		// put the byte's value into the appropriate position of the output array,
		// and move the intger value 8 bits to right (equivalent to division by 256)
		for ( int i=0; i<4; i++)
		{
			retVal[3-i] = (byte) (l & 0xff);
			l >>= 8;
		}
		
		return retVal;
	}
		
	/**
	 * Format the previously added vectors into the SSH message compliant format 
	 * 
	 * @return formatted blob containing all added vectors
	 */
	public byte[] format()
	{
		/*
		 * The total output's length contains 4 bytes (for lengths) for each vector
		 * and actual lengths (in bytes) of all vectors
		 */
		int len = 4*vectors.size();
		for ( byte[] v : vectors )
		{
			len += v.length;
		}
		
		byte[] retVal = new byte[len];
		Arrays.fill(retVal, (byte) 0);
		// current position of retVal, must be updated after each append
		int pos = 0;
		
		for ( byte[] b : vectors )
		{
			// Append the vector's length first
			System.arraycopy(intToBytes(b.length), 0, retVal, pos, 4);
			// update the pos
			pos += 4;
			// append the actual vector
			System.arraycopy(b, 0, retVal, pos, b.length);
			// and update the pos again
			pos += b.length;
		}
			
		return retVal;
	}
}
