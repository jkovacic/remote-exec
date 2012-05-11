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

/**
 * Java cryptography providers provide ASN.1 encoded DSA and ECDSA digital signatures as evident from: 
 * http://docs.oracle.com/cd/E18355_01/security.1013/b25378/oracle/security/crypto/core/DSA.html
 * and several other sources (e.g. https://forums.oracle.com/forums/thread.jspa?threadID=2147350)
 * On the other hand, SSH public key authentication protocol requires the signature to be
 * encoded as two SSH mpint values (one for R, the other one for S), as specified by RFC 5656, Section 3:
 * http://tools.ietf.org/html/rfc5656#section-3
 * 
 * This class converts ASN.1 encoded ECDSA digital signatures (returned by Signer) into
 * pairs of byte arrays that can be directly passed to SshFormatter. The class is stateful and 
 * requires the following procedure to be performed:.
 * - instantiate the class using its constructor and pass it a DER encoded ECDSA signature
 * - call convert() to parse the DER encoded signature. Both components (r and s) should be now available.
 * - success of the conversion can be checked by calling ready()
 * - call getR() and getS() to obtain values of r and s, respectively. If any of the two components
 *   is not available, 'null' will be returned.
 * 
 * @author Jernej Kovacic
 */
public class EcdsaSignatureAdapter extends DigitalSignatureAdapter 
{
	/**
	 * Constructor
	 * 
	 * @param sig - DER encoded digital signature in ASN.1 format
	 */
	EcdsaSignatureAdapter(byte[] sig)
	{
		super(sig);
	}
	
	/**
	 * Parses the ECDSA digital signature from the ASN.1 format.
	 * If the conversion was successful, R and S are available
	 * via getR() and getS(), respectively.
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
				
		sigReady = parse();
		return sigReady;
	}
	
	/**
	 * @return value of signature's component R or 'null' if not available
	 */
	public byte[] getR()
	{
		return r;
	}
	
	/**
	 * @return value of siganture's component S or 'null' if not available
	 */
	public byte[] getS()
	{
		return s;
	}
}
