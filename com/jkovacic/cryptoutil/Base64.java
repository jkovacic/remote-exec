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

import java.util.*;

/**
 * Memory efficient implementation of Base64 encoding/decoding
 * 
 * This class may process sensitive data (e.g. private keys), so every effort is made that
 * no "temporary" copies (such as temporary blocks, etc.) of data are left in memory.
 * 
 * The class contains static methods so no instantiation is necessary.
 * 
 * The encoding is defined in RFC 4648: http://tools.ietf.org/html/rfc4648
 * 
 * @author Jernej Kovacic
 *
 */

//Note: in Java, int appears to be Big Endian even on LE architectures (x86, x64)

public class Base64 
{
	private static final char[] B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray(); 
	
	/*
	 * A utility function that appends an array of chars (src) to the desired position 
	 * (indicated by offset) in another array (dest). It also handles proper formatting
	 * so that each line contains only 'lineSize' characters (line separators excluded).
	 * It also handles prepended headers (its length with line separators included is
	 * specified by 'hlen') if applicable, its length has no effect on splitting into lines 
	 * 
	 * @param dest - array of chars to append to
	 * @param src - array of chars to be copied to dest
	 * @param offset - a position in dest where the src will be copied to
	 * @param lineSize - nr. of characters in a line (line separtors excluded), may be <=0 or Integer.MAX_VALUE if splitting into lines is not required 
	 * @param ls - line separator string, may also be 'null' if not applicable  
	 * @param hlen - length of the header (including line separators), needed for proper splitting into lines
	 * 
	 * @returns a position of the first character of dest after the appended array, or -1 on an attempt to write out of dest's range 
	 */
	private static int append2array(char[] dest, char[] src, int offset, int lineSize, String ls, int hlen)
	{	
		// handle occurrence of null properly (lslen can also equal 0 in this case):
		int lslen = ( null==ls ? 0 : ls.length() );
		// When no splitting into lines is requested, it is quite elegant (in comparision with plenty of if's)
		// to set linelen into a a large number, e.g. Integer.MAX_VALUE. 
		// Note that lslen may be added to its value which may result in an overflow!
		int linelen = ( lineSize<=0 || Integer.MAX_VALUE==lineSize ? Integer.MAX_VALUE-lslen : lineSize );
		
		/*
		    Now we need to calculate the number of already complete lines and the offset within the current line:
		    Offset (of the whole dest) may be expressed as:
		        offset = hlen + nlines * (linelen + lslen) + lineoff
		    
		    Hence the lineoff can be derived as:
		        lineoff = offset - hlen - nlines * (linelen + lslen)
		        
		    To calculate it, we need the value of nlines. It can be calculated as an integer quotient:
		         nlines = (offset -hlen) / (linelen + lslen)
		         
		    When splitting into lines is not requested, (linelen+ lslen) will be set to a large value,
		    the integer quotient will always be 0 which will properly calculate nlines et al.
		 */
		int nlines = (offset-hlen) / (linelen+lslen);
		int lineoff = (offset-hlen)-nlines*(linelen+lslen);
		
		// nr. of appended characters, incl. line separators if applicable
		int ctr = 0;
		
		try
		{
			for ( char ch : src )
			{ 
				if ( lineoff >= linelen )
				{
					// A line is complete, so append the 'ls'
					// for each is not appropriate in this case as 'ls' ca be null which is properly handled by lslen
					for ( int i=0; i<lslen; i++ )
					{
						dest[offset+ctr] = ls.charAt(i);
						ctr++;
					}
					// a new line is started, so reset the lineoff
					lineoff = 0;
				}
				dest[offset + ctr] = ch;
				// do not forget to increment counters
				lineoff++;
				ctr++;
			}
		}
		catch ( ArrayIndexOutOfBoundsException ex )
		{
			return -1;
		}
		
		return offset + ctr;
	}
	
	/**
	 * Encodes a "blob" (an array of bytes) into base64 representation. Additionally 
	 * it splits the result into lines with the specified line length, inserting the 
	 * specified line separator string. If specified, it also appends a header and a 
	 * footer string, thus making the method appropriate for e.g. preparation of PEM files.
	 * 
	 * If headers, footers or line splits are not required, you are encouraged to use one of
	 * provided "macros" (versions of encode that take less parameters) that appropriately set 
	 * "unnecessary" parameters.
	 * 
	 * @param blob - an array of bytes to be encoded
	 * @param lineSize - length of a line excl. line separators, may be set to 0 if this is not required
	 * @param ls - line separator string, may be 'null' if not necessary
	 * @param header - a header string to be appended before the encoded chars, may be 'null' if not necessary
	 * @param footer - a footer string to be appended after the encoded chars, may be 'null' if not necessary
	 * 
	 * @return an array with base 64 encoded chars
	 */
	public static char[] encode(byte[] blob, int lineSize, String ls, String header, String footer)
	{
		// sanity check
		if ( null == blob || 0 == blob.length )
		{
			return null;
		}
		
		char[] b64 = null;  // a buffer where the result will be written to
		
		int lsLen = ( null==ls ? 0 : ls.length() ); // length of line separator string
		char[] lsArray = ( 0==lsLen ? null : ls.toCharArray() ); // line separator split into an array
		int totalLen = 0;
		int offset = 0;
		int hlen = 0;
	
		// First determine the correct number of output characters:
		
		// Each group of 3 bytes is encoded into 4 characters.
		// Additional quartet must be reserved for an incomplete group of 3 bytes 
		totalLen = (blob.length/3)*4;
		if ( 0!= (blob.length % 3) )
		{
			totalLen +=4;
		}
		
		// Nr. of inserted line separators (only applicable when splitting into lines is requested)
		if ( lineSize > 0 )
		{
			int lines = totalLen / lineSize;
			// an "incomplete" line counts as an additional line
			lines += ( 0==totalLen%lineSize ? 0 : 1 );
			// no line separator will be inserted after the last line, so do not count it
			totalLen += lsLen * (lines-1);
		}
		
		// Include header and footer (if specified) and 1 line separator for each
		if ( null!=header && header.length()>0 )
		{
			hlen = header.length() + lsLen;
			// now offset can be set (position of the actual first base64 character)
			offset = hlen;
			totalLen += offset;
		}
		
		// ... and do similar for the footer
		if ( null!=footer && footer.length()>0 )
		{
			totalLen += footer.length() + lsLen;
		}
		
		// The total length of the result is finally known, we may start constructing the result
		
		b64 = new char[totalLen];
		
		// Now the buffer is initialized and result can be written into it
		
		// start with the header if provided:
		if ( hlen > 0 )
		{
			// append the actual header
			offset = append2array(b64, header.toCharArray(), 0, 0, null, 0);
			//and the line separator
			if ( null != lsArray )
			{
				offset = append2array(b64, lsArray, offset, 0, null, 0);
			}
		}
		
		// incrementally calculate and append the body:
		int idx3 = 0;  // an index of the group of 3 bytes
		int temp = 0;  // a temporary buffer (at least 3 bytes long integer with supported bitwise operations) 
		char[] buf = new char[4];  // a buffer for storing temporary results of base64 encoding
		
		for ( byte b : blob )
		{
			// bit shifting operations as defined by the Base64 standard
			switch (idx3)
			{
			case 0:
				temp = (((char) b) & 0xff) << 16;
				break;
			case 1:
				temp |= (((char) b) & 0xff) << 8;
				break;
			case 2:
				temp |= (((char) b) & 0xff);
				break;
			}
			
			idx3++;
			
			if ( 3 == idx3 )
			{
				// a group of 3 bytes is complete, convert it into a 4-char base64 block
				// as defined by the standard:
				buf[0] = B64_ALPHABET[temp >> 18];
				buf[1] = B64_ALPHABET[(temp >> 12) & 0x3f];
				buf[2] = B64_ALPHABET[(temp >> 6) & 0x3f];
				buf[3] = B64_ALPHABET[temp & 0x3f];
				
				// and append the result to the buffer
				offset = append2array(b64, buf, offset, lineSize, ls, hlen);
				// reset the the index for the group of 3 bytes
				idx3 = 0;
				temp = 0;
			}
		}
		
		if ( idx3 > 0 )
		{
			// More than 0 and less than 3 bytes have remained at the end.
			// In this case the remaining bytes must be encoded as defined by the standard,
			// and an appropriate number of '=' signs must be appended.
			
			// Fill the whole buffers with '=', appropriate chars will be overwritten with the required values:
			Arrays.fill(buf, '=');
			switch (idx3)
			{
			case 2:
				// specific code for the case when two bytes remain
				buf[2] = B64_ALPHABET[(temp >> 6) & 0x3f];
				// The rest is the same as for one remaining byte, so...
				// intentionally no break!
			case 1:
				// common code for cases when any number (>0) of bytes remain
				buf[0] = B64_ALPHABET[temp >> 18];
				buf[1] = B64_ALPHABET[(temp >> 12) & 0x3f];
			}
			
			// now append the properly formatted buffer to result
			offset = append2array(b64, buf, offset, lineSize, ls, hlen);
		}
		
		// and finally append a footer if provided
		if ( null!=footer && footer.length()>0 )
		{
			// line separators are appended first if provided
			if ( null != lsArray )
			{
				offset = append2array(b64, lsArray, offset, 0, null, 0);
			}
			// followed by the actual footer
			offset = append2array(b64, footer.toCharArray(), offset, 0, null, 0);
		}
		
		
		return b64;
	}

	/**
	 * Encodes a "blob" (an array of bytes) into base64 representation. 
	 * 
	 * @param blob - an array of bytes to be encoded
	 * 
	 * @return a single line array of characters
	 */
	public static char[] encode(byte[] blob)
	{
		return encode(blob, 0, null, null, null);
	}
	
	/**
	 * Encodes a "blob" (an array of bytes) into base64 representation and splits the result
	 * (if necessary) into multiple lines (of length lineSize) separated by 'ls' 
	 * 
	 * @param blob - an array of bytes to be encoded
	 * @param lineSize - length of a line
	 * @param ls - line separator string
	 * 
	 * @return an array of characters, split into multiple lines (sparated by 'ls')
	 */
	public static char[] encode(byte[] blob, int lineSize, String ls)
	{
		return encode(blob, lineSize, ls, null, null);
	}
	
	/*
	 * Calculates the character's position in B64_ALPHABET or returns -1 if not
	 * a Base64 character.
	 */
	private static byte base64char(char c)
	{
		byte retVal = -1;
		
		if ( c >= 'A' && c <= 'Z' )
		{
			retVal = (byte) (c -'A');
		}
		else if ( c>= 'a' && c <= 'z' )
		{
			retVal = (byte) (c - 'a' + 26);
		}
		else if ( c >= '0' && c <= '9' )
		{
			retVal = (byte) (c - '0' + 52);
		}
		else if ( '+' == c )
		{
			retVal = 62;
		}
		else if ( '/' == c )
		{
			retVal = 63;
		}
		else if ( '=' == c )
		{
			retVal = 64;
		}
		else
		{
			retVal = -1;
		}
		
		return retVal;
	}
	
	/**
	 * Verifies that the given array of chars represents a valid Base64 encoding
	 * and returns the length of the original blob (array of bytes). 
	 * It is possible to verify only a part of the input array (between 'from' and 'to').
	 * 
	 *  You are encouraged to call a shorter "version" of blobLength() if you want to check the whole array
	 * 
	 * @param b64 - array of characters to be checked for Base64 validity
	 * @param from - start checking at this position of b64
	 * @param to - finish checking at this position of b64
	 * 
	 * @return number of of bytes in the decoded blob (non-negative) or -1 if b64 represents an invalid Base64 encoding
	 */
	public static int blobLength(char[] b64, int from, int to)
	{
		// sanity check
		if ( null==b64 || from<0 || to<from )
		{
			return -1;
		}
				
		byte b64code;
		int totalLen = 0;		// total length of the input array (without white spaces)
		boolean valid = true;   // is the input array a valid Base64 string (no "weird" characters except white spaces)
		int eqsigns = 0;        // nr. of '=' signs at the end of the input array
		
		for ( int i=from; i<to && i<b64.length; i++ )
		{
			b64code = base64char(b64[i]);
			
			// white spaces will be discarded.
			if ( b64code < 0 )
			{
				// switch is used to simplify "editing" a list of "permitted" white spaces
				switch ( b64[i] )
				{
				case '\r':
				case '\n':
				case '\t':
				case ' ':
					// this is white space, continue the loop
					continue;
				}  // switch
				
				// Obviously a "weird" character was found
				valid = false;
				break;  // out of for i
			}
			
			// Once '=' appears, no other characters are allowed
			if ( eqsigns > 0 && '=' != b64[i] )
			{
				valid = false;
				break;  // out of for i
			}
			
			// if still in the loop, a valid Base64 character is detected.
			// increase the counter
			if ( b64code >= 0 )
			{
				totalLen++;
			}
			
			// in case of a valid '=' (end of the array), also increase another counter
			if ( '=' == b64[i] )
			{
				eqsigns++;
			}
		}
		
		// besides the correct character set, number of valid characters must be divisible by 4
		// and no more than two '=' signs are allowed 
		if ( false==valid || 0!=(totalLen % 4) || eqsigns>2 )
		{
			return -1;
		}
		
		return (totalLen / 4) * 3 - eqsigns;
	}
	
	/**
	 * Verifies that the given array of chars represents a valid Base64 encoding
	 * and returns the length of the original blob (array of bytes). 
	 * 
	 * @param b64 - array of characters to be checked for Base64 validity
	 * 
	 * @return number of of bytes in the decoded blob (non-negative) or -1 if b64 represents an invalid Base64 encoding
	 */
	public static int blobLength(char[] b64)
	{
		// sanity check
		if ( null==b64 )
		{
			return -1;
		}
		
		return blobLength(b64, 0, b64.length);
	}
	
	/**
	 * Decodes a base64 encoded input (an array of chars) into a blob (array of bytes).
	 * It is possible to decode only a part of the input array (between 'from' and 'to').
	 * 
	 *  You are encouraged to call a shorter "version" of decode() if you want to decode the whole array
	 * 
	 * @param b64 - array of characters to be decoded
	 * @param from - start decoding at this position of b64
	 * @param to - finish decoding at this position of b64
	 * 
	 * @return decoded input text as an array of bytes
	 */
	public static byte[] decode(char[] b64, int from, int to)
	{
		// performs the sanity check, Base64 validity test and gets
		// the number of output bytes
		int blobLen = blobLength(b64, from, to);
		if ( blobLen<0 )
		{
			return null;
		}
		
		// Now we have a valid array with known length and it is possible to allocate the output buffer
		// Each group of 4 input characters will be decoded into 3 output bytes.
		// Each '=' character indicates a "missing" character of a 3-byte output "trio"
		byte[] retVal = new byte[blobLen];
		
		byte[] buf = new byte[4];  	// a temporary buffer to store a group of 4 input characters 
		int temp;					// a temporary buffer needed for conversion using bitwise operators
		
		int ctr = 0;	// position inside the output buffer
		int idx = 0;	// position inside buf
		
		/*
		   Start decoding:
		   - traverse the whole input array
		   - discard white spaces
		   - fill the buffer
		   - when filled, decode it into 3 output chars and "append" them to the output buffer
		*/
		byte b64code;
		for ( int i=from; i<to && i<b64.length; i++ )
		{
			b64code = base64char(b64[i]);
			if ( b64code < 0 )
			{
				// skip white spaces
				continue;
			}
			
			// put a valid character into buf
			buf[idx++] = b64code;
			
			if ( 4 == idx )
			{
				// the buffer is full, decode as defined by the Base64 standard
				
				if ( 64 == buf[2] )
				{
					// buffer ends with a double '='
					temp = (((buf[0] & 0x3f) << 6) | ((buf[1] & 0x3f))); 
					retVal[ctr++] = (byte) ( temp >> 4);
					break; // out of for i (presence of '=' indicates end of the input array)
				}
				else if ( 64 == buf[3] )
				{
					// buffer ends with a single '='
					temp = (((buf[0] & 0x3f) << 12) | ((buf[1] & 0x3f) << 6) | ((buf[2] & 0x3f))); 
					retVal[ctr++] = (byte) (temp >> 10);
					retVal[ctr++] = (byte) (temp >> 2);
					break;  // out of for i (presence of '=' indicates end of the input array)
				}
				else
				{
					// intermediate or complete final buffer, do not exit the for loop!
					temp = (((buf[0] & 0x3f) << 18) | ((buf[1] & 0x3f) << 12) | ((buf[2] & 0x3f) << 6) | ((buf[3] & 0x3f)));
					retVal[ctr++] = (byte) (temp >> 16);
					retVal[ctr++] = (byte) (temp >> 8);
					retVal[ctr++] = (byte) (temp);
				}
				
				// the buffer has been converted, reset its counter
				idx = 0;
			}  // if idx==4
		}  // for i
		
		return retVal;
	}
	
	/**
	 * Decodes a base64 encoded input (an array of chars) into a blob (array of bytes).
	 * 
	 * @param b64 - array of characters to be decoded
	 * 
	 * @return decoded input text as an array of bytes
	 */
	public static byte[] decode(char[] b64)
	{
		// sanity check
		if ( null == b64 )
		{
			return null;
		}
		
		return decode(b64, 0, b64.length);
	}
	
	/**
	 * Checks if the given array of chars represents a valid Base64 encoding. 
	 * It is possible to verify only a part of the input array (between 'from' and 'to').
	 * 
	 *  You are encouraged to call a shorter "version" of validBase64() if you want to check the whole array
	 * 
	 * @param b64 - array of characters to be checked for Base64 validity
	 * @param from - start checking at this position of b64
	 * @param to - finish checking at this position of b64
	 * 
	 * @return true/false
	 */
	public static boolean validBase64(char[] b64, int from, int to)
	{
		return ( blobLength(b64, from ,to) > 0 );
	}
	
	/**
	 * Checks if the given array of chars represents a valid Base64 encoding. 
	 *
	 * @param b64 - array of characters to be checked for Base64 validity
	 * 
	 * @return true/false
	 */
	public static boolean validBase64(char[] b64)
	{
		if ( null==b64 )
		{
			return false; 
		}
		
		return validBase64(b64, 0, b64.length);
	}
	
	/*
	  A unit testing function that encodes a test string
	 */
	public static void main(String[] args)
	{
		/*
		  The test string is taken from the Wikipedia article about Base64 encoding
		  http://en.wikipedia.org/wiki/Base64
		  See the article for the correct output.
		 */
		char[] test = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.".toCharArray();
		byte[] input = new byte[test.length];
		
		for ( int i =0; i<test.length; i++ )
		{
			input[i] = (byte) test[i];
		}
		
		char[] output = Base64.encode(input, 76, "\r\n", "-----BEGIN ENCOCED TEXT-----", "-----END ENCODED TEXT-----");
		System.out.print(output);
		
		System.out.print("\n\n\n");
		output = Base64.encode(input, 72, "\n");
		System.out.print(output);
		
		System.out.print("\n\n\n");
		output = Base64.encode(input);
		System.out.print(output);
		
		// Decode the last output back to the original string 
		byte[] decoded = Base64.decode(output);
		if ( null == decoded || 0 == decoded.length )
		{
			System.out.println("Base64 decoding failed");
		}
		else
		{
			System.out.print("\n\n\n");
			for ( byte b : decoded )
			{
				System.out.print((char) b);
			}
			System.out.println();
		}
	}
}
