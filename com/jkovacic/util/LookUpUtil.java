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
 * A utility class with a method that resolves an enum field (derived from SearchableByValue)
 * from the value.
 * 
 * @author Jernej Kovacic
 */
public class LookUpUtil
{
	/**
	 * Resolve the enum field whose value matches 'val'. The first occurrence of 'val' 
	 * will be returned.
	 * 
	 * @param consts - array of all enum's fields. Get it by calling Enum.values().
	 * @param val - the value to look up
	 * 
	 * @return - the first enum field with the matching value or 'null' if not found
	 */
	public static <O, T extends SearchableByValue<O>> T lookUp(T[] consts, O val)
	{
		// sanity check
		if ( null==consts || null==val )
		{
			return null;
		}
		
		T retVal = null;
		 // traverse the whole consts until an element matching valis found
		for ( T element : consts )
		{
			O temp = element.getValue();
			// if an element equals null, skip to the next one
			if ( null==temp )
			{
				continue;  // for element
			}
			
			// if the element matches val, assign the retVal and do not search further
			if ( true==temp.equals(val) )
			{
				retVal = element;
				break;  // out of for element
			}
		}
		
		return retVal;
	}
}
