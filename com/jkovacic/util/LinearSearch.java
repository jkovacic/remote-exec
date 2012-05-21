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

package com.jkovacic.util;

/**
 * A set of functions to perform linear search in an array.
 * Search complexity is linear (O(n)), so the functions are suitable 
 * for relatively short arrays. On the other hand, arrays do not need 
 * to be sorted and consecutive search is possible.
 * 
 * Generic implementation is available for objects, however Java does not
 * accept "templates" for primitive types, so very similar functions are
 * provided for some primitive types. Currently implementations for 
 * char[] and byte[] are available, it is possible to support other primitive 
 * types as well, if necessary. 
 * 
 * @author Jernej Kovacic
 */
public class LinearSearch 
{
	/*
	 * 
	 * Generic (for objects)
	 *  
	 */
	
	
	/**
	 * Searches the specified array for the specified value using
	 * the linear search algorithm.
	 * 
	 * @param array - array to be searched
	 * @param el - value to be searched for
	 * @param from - index of the first element (inclusive) to be searched
	 * 
	 * @return - position of the first occurrence (after 'from') of 'el' in the array, -1 if not found
	 */
	public static <T> int search(T[] array, T el, int from)
	{
		int retVal = -1;
		
		// sanity check
		if ( null==array || 0==array.length || null==el || from>=array.length || from<0 )
		{
			return retVal;
		}
		
		// traverse the array until an occurrence of 'el' is found
		for ( int i=from; i<array.length; i++ )
		{
			if ( el.equals(array[i]) )
			{
				retVal = i;
				// no need to traverse further
				break;  // out of for i
			}
		}
		
		return retVal;
	}
	
	/**
	 * Searches the specified array for the specified value using
	 * the linear search algorithm.
	 * 
	 * @param array - array to be searched
	 * @param el - value to be searched for
	 * 
	 * @return - position of the first occurrence of 'el' in the array, -1 if not found
	 */
	public static <T> int search(T[] array, T el)
	{
		// start searching at the start of the array
		return search(array, el, 0);
	}
	
	/**
	 * Reverse search of the specified array for the specified value using
	 * the linear search algorithm.
	 * 
	 * @param array - array to be searched
	 * @param el - value to be searched for
	 * @param from - index of the last element (inclusive) to be searched
	 * 
	 * @return - position of the last occurrence (before 'from') of 'el' in the array, -1 if not found
	 */
	public static <T> int rsearch(T[] array, T el, int from)
	{
		int retVal = -1;
		
		// sanity check
		if ( null==array || 0==array.length || null==el || from>=array.length || from<0 )
		{
			return retVal;
		}
		
		// traverse the array in reverse order until an occurrence of 'el' is found
		for ( int i=from; i>=0; i-- )
		{
			if ( el.equals(array[i]) )
			{
				retVal = i;
				// no need to traverse further
				break;  // out of for i
			}
		}
		
		return retVal;
	}
	
	/**
	 * Reverse search of the specified array for the specified value using
	 * the linear search algorithm.
	 * 
	 * @param array - array to be searched
	 * @param el - value to be searched for
	 * 
	 * @return - position of the last occurrence of 'el' in the array, -1 if not found
	 */
	public static <T> int rsearch(T[] array, T el)
	{
		// if sanity check successful, start searching at the last element
		return ( null==array ? null : rsearch(array, el, array.length-1) );
	}
	
	
	
	/*
	 * 
	 * c h a r [ ]
	 * 
	 */
	
	
	/**
	 * Searches the specified character array for the specified character using
	 * the linear search algorithm.
	 * 
	 * @param array - character array to be searched
	 * @param el - character to be searched for
	 * @param from - index of the first element (inclusive) to be searched
	 * 
	 * @return - position of the first occurrence (after 'from') of 'el' in the array, -1 if not found
	 */
	public static int search(char[] array, char el, int from)
	{
		int retVal = -1;
		
		// sanity check
		if ( null==array || 0==array.length || from>=array.length || from<0 )
		{
			return retVal;
		}
		
		// traverse the array until an occurrence of 'el' is found
		for ( int i=from; i<array.length; i++ )
		{
			if ( el == array[i] )
			{
				retVal = i;
				// no need to traverse further
				break;  // out of for i
			}
		}
		
		return retVal;
	}

	/**
	 * Searches the specified character array for the specified character using
	 * the linear search algorithm.
	 * 
	 * @param array - character array to be searched
	 * @param el - character to be searched for
	 * 
	 * @return - position of the first occurrence of 'el' in the array, -1 if not found
	 */
	public static int search(char[] array, char el)
	{
		// start searching at the start of the array
		return search(array, el, 0);
	}
	
	/**
	 * Reverse search of the specified character array for the specified character using
	 * the linear search algorithm.
	 * 
	 * @param array - character array to be searched
	 * @param el - character to be searched for
	 * @param from - index of the last element (inclusive) to be searched
	 * 
	 * @return - position of the last occurrence (before 'from') of 'el' in the array, -1 if not found
	 */
	public static int rsearch(char[] array, char el, int from)
	{
		int retVal = -1;
		
		// sanity check
		if ( null==array || 0==array.length || from>=array.length || from<0 )
		{
			return retVal;
		}
		
		// traverse the array in reverse order until an occurrence of 'el' is found
		for ( int i=from; i>=0; i-- )
		{
			if ( el == array[i] )
			{
				retVal = i;
				// no need to traverse further
				break;  // out of for i
			}
		}
		
		return retVal;
	}
	
	/**
	 * Reverse search of the specified character array for the specified character using
	 * the linear search algorithm.
	 * 
	 * @param array - character array to be searched
	 * @param el - character to be searched for
	 * 
	 * @return - position of the last occurrence of 'el' in the array, -1 if not found
	 */
	public static int rsearch(char[] array, char el)
	{
		// if sanity check successful, start searching at the last element
		return ( null==array ? null : rsearch(array, el, array.length-1) );
	}
	
	
	/*
	 * 
	 * b y t e [ ]
	 * 
	 */
	
	
	/**
	 * Searches the specified byte array for the specified byte value using
	 * the linear search algorithm.
	 * 
	 * @param array - byte array to be searched
	 * @param el - byte value to be searched for
	 * @param from - index of the first element (inclusive) to be searched
	 * 
	 * @return - position of the first occurrence (after 'from') of 'el' in the array, -1 if not found
	 */
	public static int search(byte[] array, byte el, int from)
	{
		int retVal = -1;
		
		// sanity check
		if ( null==array || 0==array.length || from>=array.length || from<0 )
		{
			return retVal;
		}
		
		// traverse the array until an occurrence of 'el' is found
		for ( int i=from; i<array.length; i++ )
		{
			if ( el == array[i] )
			{
				retVal = i;
				// no need to traverse further
				break;  // out of for i
			}
		}
		
		return retVal;
	}
	
	public static int search(byte[] array, byte el)
	{
		// start searching at the start of the array
		return search(array, el, 0);
	}
	
	public static int rsearch(byte[] array, byte el, int from)
	{
		int retVal = -1;
		
		// sanity check
		if ( null==array || 0==array.length || from>=array.length || from<0 )
		{
			return retVal;
		}
		
		// traverse the array in reverse order until an occurrence of 'el' is found
		for ( int i=from; i>=0; i-- )
		{
			if ( el == array[i] )
			{
				retVal = i;
				// no need to traverse further
				break;  // out of for i
			}
		}
		
		return retVal;
	}
	
	public static int rsearch(byte[] array, byte el)
	{
		// if sanity check successful, start searching at the last element
		return ( null==array ? null : rsearch(array, el, array.length-1) );
	}
}
