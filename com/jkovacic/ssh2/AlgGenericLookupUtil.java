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

/*
	A utility class to simplify lookups in various implementations of IEncryptionAlgorithmFamily
	
	Using generic programming ("templating") it is possible to implement "algorithms" only once and
	this way significantly improve maintainability. Without generic implementation, the code should be
	implemented in each class (deriving from IEncryptionAlgorithmFamily) separately, requiring
	to apply any changes (if necessary) in each class separately.
	
	The class is static so instantiation is not necessary and even not desired.
	The class should not be used outside of this package, for that reason even no 
	documentation comments are used.
	
	@author Jernej Kovacic
 */
abstract class AlgGenericLookupUtil
{
		
	/*
	 * Convert an instance, implementing IEncryptionalgorithmFamily (declared in com.jkovacic.cryptoutil), 
	 * into its correspondent "counterpart", implementing IsshMarshalledAlgorithm (declared in this package)
	 * 
	 * @param consts - all possible values of enums implementing ISsshMarshalledAlgorithm (generated automatically by callers)
	 * @param cuInst - an instance of IEncryptionAlgorithm to be converted
	 * 
	 * @return if possible, an instance of ISshMarshalledAlgorithm corresponding to cuInst, null otherwise
	 */
	public static <T extends ISshMarshalledAlgorithm> T lookupByCUType(T[] consts, IEncryptionAlgorithmFamily cuInst)
	{
		T retVal = null;
		
		// traverse all values in consts
		if ( null!=consts )
		{
			for ( T type : consts )
			{
				// compare to their conversions to IEncryptionFamily
				if ( cuInst==type.toCU() )
				{
					retVal = type;
					break;   // out of for type
				}
			} // for type
		}
		
		return retVal;
	}
}
