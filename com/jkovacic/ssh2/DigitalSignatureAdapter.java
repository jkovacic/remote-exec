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

/**
 * An abstract class to convert ASN.1 encoded digital signatures
 * (returned by Java crypto providers) into a SSH compliant format.
 * 
 * Actual adapter classes (e.g. for DSA or ECDSA signatures) must be
 * derived from this one. 
 * 
 * @author Jernej Kovacic
 * 
 * @see DsaSignatureAdapter, EcdsaSignatureAdapter
 */
abstract class DigitalSignatureAdapter extends DerDecoder
{
	// two components of (EC)DSA digital signature, for details, see:
	// http://en.wikipedia.org/wiki/Digital_Signature_Algorithm
	// and
	// http://en.wikipedia.org/wiki/Elliptic_Curve_DSA
	protected byte[] r = null;
	protected byte[] s = null;
	
	// is the the converted signature ready?
	protected boolean sigReady = false;
	
	/*
	 * Constructor
	 * 
	 * @param sig - DER encoded digital signature in ASN.1 format
	 */
	protected DigitalSignatureAdapter(byte[] sig)
	{
		super(sig);
		this.r = null;
		this.s = null;
		this.sigReady = false;
	}
	
	/*
	 * A common method that parses signature's R and S components from the
	 * DER encoded input. It sets 'r' and 's' which are available to derived
	 * classes' methods.
	 * 
	 * @return true or false, indicating success of the conversion
	 */
	public boolean parse()
	{
		/*
		 * Following this article:
		 * http://docs.oracle.com/cd/E18355_01/security.1013/b25378/oracle/security/crypto/core/DSA.html
		 * the DSA digital signature returned from Java cryptographic providers,
		 * is in the following ASN.1 format:
		 *  
		 *     Dss-Sig-Value  ::=  SEQUENCE  {
         *                  r       INTEGER,
         *                  s       INTEGER  }
		 */
		
		try
		{
			// parse the sequence
			SequenceRange seq = parseSequence();
			if ( null == seq )
			{
				return false;
			}
			
			// ...and check that nothing follows the initial sequence
			if ( true==moreData(seq.seqstart + seq.seqlen) )
			{
				return false;
			}
			
			// get r
			seq = parseInteger();
			if ( null == seq )
			{
				return false;
			}
			r = toByteArray(seq);
			
			// get s
			seq = parseInteger();
			if ( null == seq )
			{
				return false;
			}
			s = toByteArray(seq);
		}
		catch ( DerException ex )
		{
			return false;
		}
		
		// parsing successful
		return true;
	}
	
	/**
	 * @return true/false for availability of the converted digital signature
	 */
	public boolean ready()
	{
		return sigReady;
	}
	
	/**
	 * Start the conversion of the signature
	 * 
	 * @return true/false, indicating success of the conversion
	 */
	public abstract boolean convert();
}
