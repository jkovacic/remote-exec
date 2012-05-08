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
		// check of input parameters
		// consider null blob as an empty string, which returns "xexax"
		if ( null == blob )
		{
			return EMPTY_INPUT;
		}
		
		/*
        	required buffer length:
          	  5 * blob.length/2  (full 5-letter words)
        	+ 5                  (additional 5-letter word, composed of a 3 digit tupple)
        	+ blob.length/2      (dashes, separating 1+blob.length/2 "words")

        	Total: 6*(blob.length/2) + 5
        	
        	Note, blob.length/2 must be calculated as a rounded down integer quotient
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

	/*
	  A unit testing function that encodes a few test strings
	 */
	public static void main(String[] args)
	{
		/*
		 * Test vectors, taken from http://wiki.yak.net/589
		 * Resulting strings are "xigak-nyryk-humil-bosek-sonax",
		 * "xesef-disof-gytuf-katof-movif-baxux" and "xexax", respectively
		 */
		String[] tests = { "Pineapple", "1234567890", ""};
		
		byte[] input;
		char[] output;
		
		for ( String test : tests )
		{
			input = test.getBytes();
			output = BubbleBabble.encode(input);
		
			System.out.print(test + " --> ");
			for ( char ch : output )
			{
				System.out.print(ch);
			}
			System.out.println();
		}
	}
}
