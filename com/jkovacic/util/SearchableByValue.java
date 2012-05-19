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
 * An interface for marking enums with values assigned (of any generic type)
 * where it is possible to resolve the enum from its assigned value.
 * 
 * In order to resolve process to work properly, each enum field should
 * be assigned a unique value.
 * 
 * @author Jernej Kovacic
 *
 * @param <T> type of the value
 */
public interface SearchableByValue<T> 
{
	/**
	 * This method must be implemented properly (i.e.returning the assigned value of the enum field)
	 * as the resolve process relies on it.
	 * 
	 * @return value assigned to the enum field
	 */
	T getValue();
	
	/*
	 * a method similar to getByValue(T value) should also be declared here, however
	 * this method can only be impleneted as static, whose declarations are not permitted
	 * in interfaces.
	 */
}
