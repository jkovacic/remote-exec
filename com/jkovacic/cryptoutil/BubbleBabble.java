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

import com.jkovacic.util.*;


/**
 * A class with implementation of a bubble - babble encoding.
 * The encoding is defined at http://wiki.yak.net/589 and
 * http://wiki.yak.net/589/Bubble_Babble_Encoding.txt
 * 
 * This encoding is often used at SSH (for server verification).
 * Note that this class does not perform SHA-1 hashing so you
 * must do it yourself beforehand.
 * 
 * @author Jernej Kovacic
 * 
 * @see Base64
 */

public class BubbleBabble 
{

	// auxiliary char arrays, used by encoding algorithm
	private static final char[] VOWELS = "aeiouy".toCharArray();
	private static final char[] CONSONANTS = "bcdfghklmnprstvzx".toCharArray();
	
	// result for an empty input
	private static final char[] EMPTY_INPUT = "xexax".toCharArray();
	

	/**
	 * Calculates a bubble - babble encoding of the input blob
	 * 
	 * @param blob - a blob to be encoded
	 * @return bubble - babble encoded blob (exact nr. of the array is allocated)
	 */
	public static char[] encode(byte[] blob)
	{
		// sanity check
		// consider null blob as an empty string, which returns "xexax"
		if ( null == blob )
		{
			return EMPTY_INPUT;
		}
		
		/*
        	required buffer length:
          	  5 * floor(blob.length/2)  (full 5-letter words)
        	+ 5                         (additional 5-letter word, composed of a 3 digit tupple)
        	+ floor(blob.length/2)      (dashes, separating 1+blob.length/2 "words")

        	Total: 6 * floor(blob.length/2) + 5
		*/
		
		char[] retVal = new char[6 * (blob.length/2) + 5];
		Arrays.fill(retVal, '\u0000');
		
		// auxiliary string for a 5 letter "word" and a dash
		char [] auxstr = new char[6];
		
	    int seed = 1;
	    int pos = 1;
	    
	    int byte1;
	    int byte2;
	    
	    retVal[0] = 'x';
	    
	    for ( int i=0 ;; i+=2 )
	    {
	    	if ( i >= blob.length )
	    	{
	    		auxstr[0] = VOWELS[seed%6];
	            auxstr[1] = CONSONANTS[16];
	            auxstr[2] = VOWELS[seed/6];
	            System.arraycopy(auxstr, 0, retVal, pos, 3);
	            pos += 3;
	            break;  // out of for i
	    	}
	    	
	    	byte1 = blob[i] & 0xff;
	    	
	        auxstr[0] = VOWELS[(((byte1>>6)&3)+seed)%6];
	        auxstr[1] = CONSONANTS[(byte1>>2)&15];
	        auxstr[2] = VOWELS[((byte1&3)+(seed/6))%6];
	        
	        if ( i+1 >= blob.length )
	        {
	        	System.arraycopy(auxstr, 0, retVal, pos, 3);
	            pos += 3;
	            break;  // out of for i
	        }

	        byte2 = blob[i+1] & 0xff;
	        auxstr[3] = CONSONANTS[(byte2>>4)&15];
	        auxstr[4] = '-';
	        auxstr[5] = CONSONANTS[byte2&15];
	        System.arraycopy(auxstr, 0, retVal, pos, 6);
	        pos += 6;
	        seed = (seed*5 + byte1*7 + byte2)%36;
	    }  // for i 
	    
	    retVal[pos] = 'x';
	    
		return retVal;
	}
	
	/**
	 * Verifies if the given char sequence COULD represent a bubble-babble encoded
	 * blob. Only the sequence's length and "type" of characters (valid vowels or consonants)
	 * at each position are checked. Checksums are not checked. As this a part of the decoding 
	 * process, decode() should be run for the complete verification.
	 * 
	 * @param bb - char array to be verified
	 * 
	 * @return true/false
	 */
	public static boolean validBubbleBabble(char[] bb)
	{
		// sanity check
		if ( null==bb )
		{
			return false;
		}
		
		/*
		 * The valid length is n*6+5:
		 * n five-char tuples + '-'
		 * plus additional five-char tuple without the '-'
		 */
		if ( (bb.length%6)!=5 )
		{
			return false;
		}
		
		/*
		 * The valid bubble babble string always begins and ends with 'x'
		 */
		if ( bb[0]!='x' || bb[bb.length-1]!='x' )
		{
			return false;
		}
		
		boolean retVal = true;
		
		// check if expected characters are placed to their appropriate positions
		for ( int i=0; i<bb.length; i++ )
		{
			// Positions of 5, 11, 17, etc. are reserved for dashes
			if ( 5 == (i%6) )
			{
				if ( '-' != bb[i] )
				{
					retVal = false;
					break; // out of for i
				}
				
				// proceed to the next character
				continue;  // for i
			}
			
			if ( 0 == i%2 )
			{
				// valid consonants are expected at even-numbered positions (0, 2, 4, 6, 8, etc
				if ( LinearSearch.search(CONSONANTS, bb[i]) < 0 )
				{
					retVal = false;
					break;
				}
			}
			else if ( LinearSearch.search(VOWELS, bb[i]) < 0 )
			{
				// while valid vowels are expected at odd-numbered positions (1, 3, 7, etc.)
				retVal = false;
				break;
			}
		}
		
		return retVal;
	}
	
	/*
	 * Decodes the first part (the first 3 characters) of a bubble-babble tuple into a byte value.
	 * Parameters represent values of the typical bubble-babble tuple: <a1 a2 a3 a4 - a5>.
	 * 
	 * @param a1 - first value of the bubble-babble tuple
	 * @param a2 - second value of the bubble-babble tuple
	 * @param a3 - third value of the bubble-babble tuple
	 * @param c - bubble-babble checksum, depending on previous tuples
	 * 
	 * @return byte value of the bubble-babble parameters or -1 in case of invalid values
	 */
	private static int decodeGroupOf3(int a1, int a2, int a3, int c)
	{
		int retVal = 0;
		
		// 2 most significant bits of retVal:
		int first = (a1 - (c%6) + 6) % 6;
		
		// value check
		if ( first>=4 || a2>16 )
		{
			return -1;
		}
		
		// 4 central bits of retVal
		int second = a2;
		
		// and 2 least significant bits of retVal:
        int third = (a3 - (c/6%6) + 6) % 6;
        // value check
        if ( third>=4 )
        {
        	return -1;
        }
            
        // finally compose the retVal
        retVal = first<<6 | second<<2 | third;
		
		return retVal;
	}
	
	/* 
	 * Decodes the second part (the final 2 characters) of a bubble-babble tuple into a byte value.
	 * Parameters represent values of the typical bubble-babble tuple: <a1 a2 a3 a4 - a5>.
	 * 
	 * @param a4 - fourth value of the bubble-babble tuple
	 * @param a5 - fifth value of the bubble-babble tuple
	 * 
	 * @return byte value of the bubble-babble parameters or -1 in case of invalid values
	 */
	private static int decodeGroupOf2(int a4, int a5)
	{
		int retVal = 0;
		
		// value check
		if ( a4>16 || a5>16 )
        {
        	return -1;
        }
		
		// compose the retVal, i.e 4 bytes from each parameter:
        retVal = (a4<<4) | a5;
        
        return retVal;
	}
	
	/**
	 * Decodes a char sequence, presumably representing a bubble-babble encoding,
	 * into an array of bytes.
	 * 
	 * @param bb - char sequence to be decoded
	 * 
	 * @return corresponding byte array or 'null' in case of invalid 'bb'
	 */
	public static byte[] decode(char[] bb)
	{
		
		// Decoding process is inverse to encoding.
		
		// sanity check
		if ( null==bb || false==validBubbleBabble(bb) )
		{
			return null;
		}
			
		/*
		 * As derived in encode(), the bubble-babble string's length
		 * equals to: bb.length = 6 * floor(blob.length) + 5
		 * From this, the following relation can be derived:
		 * floor(blob.length) = (bb.length - 5) / 6
		 * 
		 * Two values of the inknown blob.length solve the equation:
		 * (bb.length - 5) / 3   and
		 * 1 + (bb.length - 5) / 3
		 * 
		 * As it will be shown later, the actual solution is determined
		 * by one bubble babble character.
		 */
		int retLen = (bb.length-5)/3;
		
		// if the third character from the end equals 'x', no extra byte will be appended 
		if ( 'x' != bb[bb.length-3] )
		{
			retLen++;
		}
		// now the total retVal's length is known 
		byte[] retVal = new byte[retLen];
		
		// checksum:
		int checksum = 1;
		int byte1 = 0;
		int byte2 = 0;
		// current position inside retVal:
		int retPos = 0;
		// numeric values of the a <a1 a2 a3 a4 - a5> tuple:
		int a1, a2, a3, a4, a5;
		
		// convert all complete tuples (i.e. all except the last one)
		// into a pair of characters:
		for ( int i=0; i<bb.length/6; i++ )
		{
			// get numeric values of the tuple:
			a1 = LinearSearch.search(VOWELS, bb[i*6+1]);
			a2 = LinearSearch.search(CONSONANTS, bb[i*6+2]);
			a3 = LinearSearch.search(VOWELS, bb[i*6+3]);
			a4 = LinearSearch.search(CONSONANTS, bb[i*6+4]);
			a5 = LinearSearch.search(CONSONANTS, bb[i*6+6]);
			
			// and decode them into a pair of characters:
	        byte1 = decodeGroupOf3(a1, a2, a3, checksum);
            byte2 = decodeGroupOf2(a4, a5);
            
            // if a tuple was invalid, the corresponding byte will be set to -1
            if ( byte1<0 || byte2<0 )
            {
            	return null;
            }
	        
            // update the checksum:
	        checksum = (checksum*5 + byte1*7 + byte2) % 36;
	        
	        // and finally "append" the bytes to retVal:
	        retVal[retPos++] = (byte) (byte1 & 0xff);
	        retVal[retPos++] = (byte) (byte2 & 0xff);
		}
		
		// The final tuple consists of three bytes only and must 
		// be processed a bit differently. 
		a1 = LinearSearch.search(VOWELS, bb[bb.length-4]);
		a2 = LinearSearch.search(CONSONANTS, bb[bb.length-3]);
		a3 = LinearSearch.search(VOWELS, bb[bb.length-2]);
		
		// If the third character from the bb's end equals 'x' (its numeric value is 16),
		// no extra character will be appended, just check the checksums:
		if ( 16==a2 )
		{
			if ( a1!= (checksum%6) || a3!=(checksum/6) )
			{
				return null;
			}
		}
		else
		{
			// otherwise decode one more character and append it to retVal
			byte1 = decodeGroupOf3(a1, a2, a3, checksum);
			if ( byte1<0 )
			{
				return null;
			}
			retVal[retPos++] = (byte) (byte1 & 0xff);
		}
		
		return retVal;
	}
	
	/*
	  A unit testing function that encodes a few test strings
	 */
	public static void main(String[] args)
	{
		/*
		 * Test vectors, taken from http://wiki.yak.net/589
		 * Resulting strings are "xigak-nyryk-humil-bosek-sonax",
		 * "xesef-disof-gytuf-katof-movif-baxux" and "xexax", respectively.
		 * The bubble-babble encodings are decoded back to original test vectors:
		 */
		String[] tests = { "Pineapple", "1234567890", ""};
		
		byte[] input;
		char[] output;
		String orig;
		
		for ( String test : tests )
		{
			input = test.getBytes();
			output = BubbleBabble.encode(input);
			orig = new String(BubbleBabble.decode(output));
		
			System.out.print(test + " --> ");
			for ( char ch : output )
			{
				System.out.print(ch);
			}
			System.out.print(" --> ");
			System.out.println(orig);
		}
	}
}
