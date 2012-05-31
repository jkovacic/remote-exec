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
 * A convenience class to convert an array of bytes to a string with its
 * hexadecimal representation (either upper- or lower cased) and vice versa.
 * 
 * All methods are static so there is no need to instantiate the class.
 * 
 * @author Jernej Kovacic
 */
public class ByteHex 
{
	private static char[] HEX_DIGITS_UPPER_CASE = "0123456789ABCDEF".toCharArray();
	private static char[] HEX_DIGITS_LOWER_CASE = "0123456789abcdef".toCharArray();
	
	/*
	 * Internal function that converts a blob (an array of bytes) into 
	 * its hexadecimal representation, a string with colon separated pairs
	 * of hex. digits.
	 * 
	 * The method is private and called by public methods that set the 
	 * hex "alphabet" depending on user specified settings.
	 * 
	 * @param bytes - blob to be encoded
	 * @param digits - hex "alphabet" (an array of chars with at least 16 members) to be used, typically one of classes private arrays
	 * 
	 * @return
	 */
	private static char[] convertToHex(byte[] bytes, char[] digits)
	{
		// sanity check, including length of digits (at least 16 chars.)
		if ( null==bytes || null==digits || 0==bytes.length || digits.length<16 )
		{
			return null;
		}
		
		// allocate the appropriate size of the output:
		// two hex digits (chars) for each byte + 
		// 1 byte (colon) for each byte except the last one 
		char[] retVal = new char[3*bytes.length-1];
		
		int pos = 0;
		for ( int i=0; i<bytes.length; i++ )
		{
			int b = bytes[i] & 0xff;
			retVal[pos++] = digits[b>>4];
			retVal[pos++] = digits[b&0x0f];
			
			if ( i<bytes.length-1)
			{
				retVal[pos++] = ':';
			}
		
		}
		
		return retVal;
	}
	
	/**
	 * Converts a blob (array of bytes) to a string of semicolon separated string
	 * of hex pairs, e.g. "2f:aa:04".
	 * 
	 * Case of the hex digits between 'a' and 'f' depends on 'uppercase'
	 * 
	 * @param bytes - blob to be encoded
	 * @param uppercase - whether hex digits of the output should be represented by upper case letters
	 * 
	 * @return hex encoded blob as a string, represented as colon separated pairs of hex digits
	 */
	public static char[] toHex(byte[] bytes, boolean uppercase)
	{
		char[] digits = ( uppercase ? HEX_DIGITS_UPPER_CASE : HEX_DIGITS_LOWER_CASE );
		return convertToHex(bytes, digits);
	}
	
	/**
	 * Converts a blob (array of bytes) to a string of semicolon separated string
	 * of hex pairs, e.g. "2f:aa:04".
	 * 
	 * Note that hex digits between 'a' and 'f' are represented as lower case characters
	 * 
	 * @param bytes - blob to be encoded
	 * 
	 * @return hex encoded blob as a string, represented as colon separated pairs of hex digits
	 */
	public static char[] toHex(byte[] bytes)
	{
		return toHex(bytes, false);
	}
	
	/*
	 * Does the input represent a valid hex string, i.e a group of colon
	 * separated pairs hex digits, e.g. "1d:45:23:A3"?
	 * The method is case insensitive. 
	 *
	 * @param hex - string input to be validated
	 * 
	 * @return true if the input represents a valid hex string, false otherwise
	 */
	private static boolean validHexString(char[] hex)
	{
		boolean retVal = false;
		
		// the "loop" is is executed only once and broken as soon as something invalid is detected
		exit:
		for ( int iii=0; 0==iii; iii++ )
		{
			// check of input parameters, incl., the input's length
			if ( null==hex || 0==hex.length || 2!=hex.length%3 )
			{
				break exit;
			}
			
			// process groups of 3 characters
			for ( int i=0; i<hex.length; i++ )
			{
				switch ( i%3 )
				{
				case 0:
				case 1:
					// the first and second char of the group must be valid hex digits
					if ( !( (hex[i]>='0' && hex[i]<='9') || 
							(hex[i]>='A' && hex[i]<='F') ||
							(hex[i]>='a' && hex[i]<='f') ) )
					{
						break exit;
					}
					break;
				
				case 2:
					// the third one must be a colon (':')
					if ( ':' != hex[i] )
					{
						break exit;
					}
					break;
					
				default:
					// should never occur, but...
					break exit;
				}  // switch
			}
			
			// If no break has been called, the hex input is considered valid.
			// Set retVal to true
			retVal = true;
		}  // for
		
		return retVal;
	}
	
	/*
	 * Converts a valid hex digit ('0' to '9' and 'a' to 'f' or 'A' to 'F')
	 * into its numeric value (0 to 15).
	 * 
	 * Note that the method is private, all validity checks are done beforehand so 
	 * there is no extra error handling inside this method.
	 * 
	 * @param digit - a hex digit
	 * 
	 * @return digit's numeric value
	 */
	private static int hexToDec(char digit)
	{
		int retVal = -1;
		
		if ( digit>='0' && digit<='9' )
		{
			retVal = digit-'0'; 
		}
		
		if ( digit>='A' && digit<='F' )
		{
			retVal = 10 + digit - 'A';
		}
		
		if ( digit>='a' && digit<='f' )
		{
			retVal = 10 + digit -'a';
		}
		
		return retVal;
	}
	
	/**
	 * Converts a string with a hex representation into its corresponding array of bytes
	 * 
	 * @param hex - a string with colon separated bytes in hexadecimal notation 
	 * 
	 * @return an array of bytes corresponding to 'hex' or null if input is invalid
	 */
	public static byte[] toBytes(char[] hex)
	{
		// sanity check
		if ( null==hex || 0==hex.length || false==validHexString(hex) )
		{
			return null;
		}

		// allocate the appropriate size of the output array
		byte[] retVal = new byte[(hex.length+1)/3];
		int pos = 0;
		int nib1;
		int nib2;
		
		// each byte (except the last one) is represented by a triple 'xy:'
		// where x and y represent valid 4-bit hex digits (nibbles)
		for ( int i=0; i<hex.length; i+=3 )
		{
			nib1 = hexToDec(hex[i]);
			nib2 = hexToDec(hex[i+1]);
			
			retVal[pos++] = (byte) ( ( (nib1&0x0f)<<4 ) | (nib2&0x0f) );
		}
		
		return retVal;
	}
	
	public static void main(String[] args)
	{
		char[] hex = "57:fe:9f:5e:78:94:6F:a9:19:28:Ce:94:14:62:53:fd".toCharArray();
		byte[] bytes = toBytes(hex);
		
		if ( null==bytes )
		{
			System.err.println("Conversion to bytes failed");
		}
		else
		{
			for ( byte b : bytes )
			{
				System.out.print(b + "  ");
			}
			System.out.println();
		}
		
		byte[] barray = { 87, -2, -97, 94, 120, -108, 111, -87, 25, 40, -50, -108, 20, 98, 83, -3 };
		char[] hexchars = toHex(barray);
		if ( null==hexchars )
		{
			System.out.println("Conversion to hex failed");
		}
		else
		{
			System.out.println(hexchars);
		}
	}
	
}
