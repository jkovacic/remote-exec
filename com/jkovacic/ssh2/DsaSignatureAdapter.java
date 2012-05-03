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

import java.util.Arrays;

import com.jkovacic.cryptoutil.*;

/**
 * Java cryptography providers provide ASN.1 encoded digital signatures as evident from: 
 * http://docs.oracle.com/cd/E18355_01/security.1013/b25378/oracle/security/crypto/core/DSA.html
 * On the other hand, SSH public key authentication protocol requires IEEE P1363 
 * encoded digital signatures. The IEEE P1363 standard is not available free of charge,
 * fortunately it is well described in this article:
 * http://www.codeproject.com/Articles/25590/Cryptographic-Interoperability-Digital-Signatures
 * 
 * This class converts ASN.1 encoded DSA digital signatures (returned by Signer) into
 * SSH compliant format. The class is stateful and requires calling of several methods:
 * - instantiate the class using its constructor and pass it a DER encoded DSA signature
 * - call convert() to start the conversion
 * - success of the conversion can be checked by calling ready()
 * - the converted signature may be obtain via getSshSignature() (or null will be returned if not available)
 * 
 * Note: at the moment only signature by 1024-bit keys are supported. Support for
 * longer keys will be available soon. Then the API may also be changed.
 * 
 * @author Jernej Kovacic
 */

public class DsaSignatureAdapter extends DerDecoder
{
	// two components of DSA digital signature, for details, see:
	// http://en.wikipedia.org/wiki/Digital_Signature_Algorithm
	private byte[] r = null;
	private byte[] s = null;
	
	// is the signature in SSH compliant format available?
	boolean sigReady = false;
	
	// SSH compliant digital signature
	private byte[] sshSignature = null;
	
	/**
	 * Constructor
	 * 
	 * @param sig - DER encoded digital signature in ASN.1 format
	 */
	public DsaSignatureAdapter(byte[] sig)
	{
		super(sig);
		this.r = null;
		this.s = null;
		this.sshSignature = null;
		this.sigReady = false;
	}
	
	/**
	 * The function that parses the DER encoded signature and prepares it in 
	 * the SSH compliant (IEEE P1363) format.
	 * 
	 * @return true/false, indicating success of the conversion
	 */
	public boolean convert()
	{
		// nothing to do if the signature is already available
		if ( true == sigReady )
		{
			return true;
		}
		
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
		
		/*
		 * r and s are parsed from the structure, now they need to be converted
		 * into the IEEE P1363 format. This format requires both components to be 
		 * 20 bytes long. If any of them is shorter, the appropriate number of zeros
		 * is padded in front of the too short component. It is also possible that 
		 * a component is one byte longer than this. This comes from the DER encoding
		 * that strictly preserves the sign of integers (defined by the most significant
		 * bit). If the MSB of the original 20-byte integer is 1, additional byte (equaling 0)
		 * is prepended the component marking, that the the integer is positive. In such a case,
		 * this byte is omitted and remaining 20 bytes are copied into the IEEE P1363 
		 * compliant signature. More info about this at:
		 * http://www.codeproject.com/Articles/25590/Cryptographic-Interoperability-Digital-Signatures#xx3240277xx
		*/
		
		// the SSH compliant signature will be exactly 40 bytes long:
		// 20 bytes for r, immediately followed by 20 bytes for s:
		sshSignature = new byte[40];
		
		// Java should initialize the array to zeros but it doesn't hurt to do it manually as well:
		Arrays.fill(sshSignature, (byte) 0);
		
		// copy the appropriate number of bytes of r:
		System.arraycopy(
				r, 
				(r.length>20 ? 1 : 0),
			    sshSignature, 
			    (r.length>20 ? 0 : 20-r.length),
			    (r.length>20 ? 20 : r.length) );
		
		// followed by the appropriate number of bytes of s:
	    System.arraycopy(
	    		s, 
	    		(s.length>20 ? 1 : 0),
	    		sshSignature, 
	    		(s.length>20 ? 20 : 40-s.length),
			    (s.length>20 ? 20 : s.length) );

		// if reaching this point, the conversion is successful
		sigReady = true;
		return true;
	}
	
	/**
	 * @return true/false for availability of the SSH compliant DSA digital signature
	 */
	public boolean ready()
	{
		return sigReady;
	}
	
	/**
	 * @return SSH compliant DSA digital signature
	 */
	public byte[] getSshsignature()
	{
		return ( true==sigReady ? sshSignature : null );
	}
}
