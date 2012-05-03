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
 * A class implementing basic DER decoding functionality.
 * 
 * When a class is instantiated with the actual DER input, the DER
 * contents must be sequentially parsed, so a detailed knowledge of
 * expected fields is necessary.
 * 
 * Although it would be possible to use this class directly, typically a more 
 * specialized class will be derived from it.
 * 
 * ASN.1 specification, DER is based on, is available at:
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 * 
 * @author Jernej Kovacic
 *
 * @see DerDecoderPrivateKey
 */
public class DerDecoder 
{
	// contents in DER format
	private byte[] der = null;
	// cursor with the current position of the parser within der
	private int pos = 0;
	
	/**
	 * Constructor
	 * 
	 * Initializes the class with the input in DER encoding
	 * 
	 * @param blob - contents n DER encoding to be parsed
	 */
	public DerDecoder(byte[] blob)
	{
		this.der = blob;
		this.pos = 0;
		
		// "protection" from null dereferencing:
		if ( null == this.der )
		{
			this.der = new byte[0];
		}
	}
	
	/*
	 * Get the byte at the current position
	 * 
	 * @return a byte at the current position
	 * 
	 * @throws DerException when out of range
	 */
	private byte readByte() throws DerException
	{
		if ( pos >= der.length )
		{
			throw new DerException("Attempting to read a byte out of range");
		}
		
		return der[pos++];
	}
	
	/**
	 * Parses the length of the next ASN.1 field at the current position
	 * 
	 * @return length of the next field in bytes
	 * 
	 * @throws DerException in case of an invalid length specification
	 */
	protected int parseLength() throws DerException
	{
		int retVal = 0;
		int remaining = 0;
		
		byte b = readByte();
		
		/*
		 * If the most significant bit is set to 1, the actual length is encoded
		 * in the following bytes. The actual number of bytes ( max. 127) is encoded 
		 * by the remaining bits of this byte.
		 * If the most significant bit is set to 0, the length is encoded by this byte,
		 * immediately followed by the actual data. 
		 */
		if ( 0 == (b & 0x80) )
		{
			retVal = b & 0xff;
		}
		else
		{
			// nr. of bytes with length
			remaining = (b & 0xff) & 0x7f;
		}
		
		// zero length is invalid
		if ( 0==retVal && 0==remaining )
		{
			throw new DerException("Invalid length of a data structure");
		}
		
		// The function returns int, so max. 4 length bytes are supported by this implementation.
		// This is not a constraint for the current applications
		if ( remaining > 4 )
		{
			throw new DerException("Data structure too long");
		}
		
		// If the length is encoded in several bytes, 
		// compose an int by simple bit shifting
		// (equivalent to multiplication by 256)
		// Note: in Java, int appears to be Big Endian even on LE architectures (x86, x64)
		while ( remaining>0 )
		{
			b = readByte();
			retVal <<= 8;
			retVal |= b & 0xff;
			remaining--;
		}
		
		// Check validity of the result.
		// It must not be negative and it must not exceed the actual DER array
		if ( retVal<0 || (pos+retVal)>der.length )
		{
			throw new DerException("Invalid length");
		}
		
		return retVal;
	}
	
	/**
	 * Parses the ASN.1 sequence, i.e. determines its start and length
	 * 
	 * Note: it does not read the actual sequence data and the "cursor"
	 * is set to the first byte of the actual sequence data!
	 * 
	 * @return sequence start and length
	 * 
	 * @throws DerException in case of invalid syntax of the sequence
	 */
	protected SequenceRange parseSequence() throws DerException
	{
		byte type = readByte();
		
		// ASN.1 sequence starts with the code 0x30...
		if ( 0x30 != (type & 0xff) )
		{
			throw new DerException("Invalid ASN.1 sequence code");
		}
		
		// ... followed by the sequence length
		int len = parseLength();
		if ( (pos+len) > der.length )
		{
			throw new DerException("Sequence too long");
		}
		
		SequenceRange retVal = new SequenceRange();
		retVal.seqlen = len;
		retVal.seqstart = pos;
		
		return retVal;
	}
	
	/**
	 * Parses the ASN.1 integer, i.e. determines its start position and length
	 * Length can be much longer than 4 bytes, so the right Java equivalent 
	 * would be BigInteger, not int.
	 * 
	 * The cursor is moved to the first byte of the next field.
	 * 
	 * @return integers tart and length in bytes
	 * 
	 * @throws DerException in case of invalid syntax of the integer
	 */
	protected SequenceRange parseInteger() throws DerException
	{	
		byte b = readByte();
		
		// ASN.1 integer starts with the code 0x02...
		if ( 0x02 != (b & 0xff) )
		{
			throw new DerException("Invalid code for ASN.1 integer");
		}
		
		// followed by the length of the integer
		int len = parseLength();
	
		SequenceRange retVal = new SequenceRange();
		retVal.seqstart = pos;
		retVal.seqlen = len;
		
		// move the cursor to the end of the integer
		pos += len;
		
		return retVal;
	}
	
	/**
	 * Copies a sub array the DER array to another byte[] array.
	 * If the range is not correct (e.g. not specified, invalid fields,
	 * pointing out of the DER range...), null will be returned
	 * 
	 * @param range to be copied
	 * 
	 * @return subarray 
	 */
	protected byte[] toByteArray(SequenceRange range)
	{
		// Input paramater must be specified, its fields must not be negative,
		// and it must not point out of the range
		if ( 
				null==range ||
				range.seqlen<0 || range.seqstart<0 ||
				(range.seqstart + range.seqlen)>der.length
			)
		{
			return null;
		}
			
		// allocate the new array...
		byte[] retVal = new byte[range.seqlen];
		
		// ...and copy the appropriate bytes of der into it
		for ( int i=0; i<range.seqlen; i++ )
		{
			retVal[i] = der[range.seqstart + i];
		}
		
		return retVal;
	}
	
	/**
	 * A convenience function to convert a short array of bytes directly into
	 * an integer. Due to Java int limitations, range must not be longer than 4 bytes.
	 * 
	 * @param seq - a range to be converted
	 * 
	 * @return integer value of the range
	 * 
	 * @throws DerException if something is invalid
	 */
	protected int toInt(SequenceRange seq) throws DerException
	{
		// Thorough check of input parameters:
		
		// - range must be specified,...
		if ( null == seq )
		{
			throw new DerException("No range specified");
		}
		
		// - ...with valid fields,...
		if ( seq.seqstart<0 || seq.seqlen<0 )
		{
			throw new DerException("Invalid range parameters");
		}
		
		// - ...and must not point out of the DER array.
		if ( seq.seqstart+seq.seqlen >= der.length )
		{
			throw new DerException("Out of valid range");
		}
		
		// - finally, length of the range must not be longer than 4 bytes
		if ( seq.seqlen > 4 )
		{
			throw new DerException("Integer too long");
		}
		
		// Simply convert the range using bit shifting
		// (an equivalent to multiplication by 256)
		// Note: in Java, int appears to be Big Endian even on LE architectures (x86, x64)
		int retVal = 0;
		
		for ( int i=0; i<seq.seqlen; i++ )
		{
			retVal <<= 8;
			retVal |= (der[(seq.seqstart+i) & 0xff]);
		}
		
		
		return retVal;
	}
	
	/**
	 * Does anything follow the current position of the cursor?
	 * 
	 * @return true/false
	 */
	protected boolean moreData()
	{
		return ( pos < der.length );
	}
	
	/**
	 * Are there more data after from?
	 * 
	 * @param from
	 * 
	 * @return true/false
	 */
	protected boolean moreData( int from)
	{
		return ( from < der.length );
	}
	
	/**
	 * Could field, pointed by the cursor,  represent an ASN.1 sequence?
	 * Only the code is checked, not the whole sequence.
	 * 
	 * @return true/false
	 */
	protected boolean isASN1Sequence()
	{
		return ( pos<der.length && 0x30==der[pos] );
	}
	
	/**
	 * Could field, pointed by the cursor,  represent an ASN.1 integer?
	 * Only the code is checked, not the whole possible integer sequence.
	 * 
	 * @return true/false
	 */
	public boolean isASN1Int()
	{
		return ( pos<der.length && 0x02==der[pos] );
	}
	
	/**
	 * A convenience internal structure with two integer fields,
	 * internally used to store data about a byte range.
	 * 
	 * Public methods should not accept or return instances of this class.
	 * 
	 * @author Jernej Kovacic
	 */
	protected class SequenceRange
	{
		// Start of a byte range within DER
		public int seqstart = 0;
		// Length of the byte range
		public int seqlen = 0;
	}
	
	/**
	 * An exception used internally within this class.
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

}
