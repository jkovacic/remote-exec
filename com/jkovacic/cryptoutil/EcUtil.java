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
import java.math.*;
import java.security.spec.*;

/**
 * A collection of functions handling EC related tasks. All operations are
 * defined at SEC1:
 * Standards for Efficient Cryptography Group, "Elliptic Curve Cryptography"
 * http://www.secg.org/download/aid-780/sec1-v2.pdf
 * 
 * All functions are static so no instantiation of the class is necessary
 * 
 * @author Jernej Kovacic
 */
public class EcUtil 
{
	// A numeric code for representation of an ECPoint in uncompressed form
	private static final byte ECPOINT_UNCOMPRESSED_FORM_INDICATOR = 0x04;
	
	/**
	 * Does this library support the given algorithm.
	 * The function is typically used to filter out non EC algorithms.
	 * 
	 * @param alg - asymmetric encryption algorithm
	 * 
	 * @return true/false
	 */
	public static boolean supportedEcDomain(AsymmetricAlgorithm alg)
	{
		// sanity check
		if ( null == alg )
		{
			return false;
		}
		
		boolean retVal = false;
		switch (alg)
		{
		case ECDSA_NISTP256:
		case ECDSA_NISTP384:
		case ECDSA_NISTP521:
			retVal = true;
			break;
			
		default:
			retVal = false;
		}
		
		return retVal;
	}
	
	/**
	 * Returns EC crypto specifications for the given algorithm
	 * 
	 * @param alg - algorithm identifier
	 * 
	 * @return specifications for the 'alg' or 'null' if unsupported
	 */
	public static ECParameterSpec getSpec(AsymmetricAlgorithm alg)
	{
		// sanity check
		if ( null == alg )
		{
			return null;
		}
		
		ECParameterSpec retVal = null;
		
		// Specifications for supported algorithms have been assigned
		// as static members of the class
		switch (alg)
		{
		case ECDSA_NISTP256:
			retVal = EC_NISTP256;
			break;
			
		case ECDSA_NISTP384:
			retVal = EC_NISTP384;
			break;
			
		case ECDSA_NISTP521:
			retVal = EC_NISTP521;
			break;
			
		default:
			retVal = null;
		}
		
		return retVal;
	}
	
	/**
	 * Converts the given octet string (defined by ASN.1 specifications) to a BigInteger
	 * As octet strings always represent positive integers, a zero-byte is prepended to
	 * the given array if necessary (if is MSB equal to 1), then this is converted to BigInteger
	 * The conversion is defined in the Section 2.3.8
	 * 
	 * @param os - octet string to be converted
	 * 
	 * @return BigInteger representation of 'os'
	 */
	public static BigInteger octetStringToInteger(byte[] os)
	{
		// sanity check
		if ( null == os )
		{
			return null;
		}
		
		int mlen = os.length;
		if ( 0 == mlen )
		{
			return BigInteger.ZERO;
		}
		
		// if the 'os' could represent a negative integer (if its MSB is set to 1),
		// an additional zero-byte must be prepended to it so it represents a positive integer
		int retlen = mlen;
		
		if ( os[0]<0 )
		{
			retlen++;
		}
		
		byte[] auxb = new byte[retlen];
		Arrays.fill(auxb, (byte) 0);
		
		System.arraycopy(os, 0, auxb, retlen-mlen, mlen);
		
		return new BigInteger(auxb);
	}
	
	/**
	 * Converts an octet string (actually should be a bit string but bytes are already composed
	 * from bits, hence an octet string), representing an EC point, to an instance of
	 * ECPoint. Right now only the uncompressed form (the first non zero byte equaling 4)
	 * of point representation is supported. It looks that SSH key generators (in particular OpenSSH's
	 * ssh-keygen) never encode ECPoints in a compressed form.
	 * The conversion is specified in sections 2.3.4, 2.3.6 and appendix C3.
	 * 
	 * @param alg - algorithm type, needed for checking and properly generation of the EC point
	 * @param os - octet string with an EC point representation in uncompressed form
	 * 
	 * @return instance of ECPoint or null if anything fails
	 */
	public static ECPoint octetStringToEcPoint(AsymmetricAlgorithm alg, byte[] os)
	{
		if ( null == os || null == alg )
		{
			return null;
		}
		
		// Currently only EC points in uncompressed form are supported.
		// See the section 2.3.6
		if ( false == isUncompreesedPoint(os) )
		{
			return null;
		}
		
		// Expected size of elements of 'os', depending on EC specifications
		int m = 0;
		switch (alg)
		{
		case ECDSA_NISTP256:
			m = 32;
			break;
			
		case ECDSA_NISTP384:
			m = 48;
			break;
			
		case ECDSA_NISTP521:
			m = 66;
			break;
			
		default:
			// unsupported algorithm or EC domain
			return null;
		}
		
		int mlen = os.length;
		if ( 0 == mlen )
		{
			return null;
			//return new byte[0];
		}
		
		// strip off leading zero-bytes
		int start = 0;
		while ( start<mlen && 0x00==os[start] )
		{
			start++;
		}
		
		// os contains just zeroes. Invalid EC point representation
		if ( mlen == start )
		{
			return null;
		}
		
		// The coordinates actually start after the compression indicator
		// (1 byte, its value was already checked)
		start++;
		if ( (mlen-start) != 2*m )
		{
			return null;
		}
		
		// get octet string values of both coordinates (see Section 2.3.6)
		byte[] xp = new byte[m];
		byte[] yp = new byte[m];
		System.arraycopy(os, start, xp, 0, m);
		System.arraycopy(os, start+m, yp, 0, m);
		
		// and create an instance of ECPoint
		return new ECPoint(
				octetStringToInteger(xp),
				octetStringToInteger(yp));
	}
	
	/**
	 * A convenience function to determine whether the first non-zero byte is
	 * equal to a specific value. Typically used to determine whether a blob
	 * represents an EC point in compressed or uncompressed form.
	 * 
	 * @param p - array of bytes to check
	 * @param id - expected value of the first non-zero byte
	 * 
	 * @return whether the first non-zero byte is equal to id
	 */
	public static boolean startsWith(byte[] p, byte id)
	{
		// sanity check
		if ( null == p || 0 == p.length )
		{
			return false;
		}
		
		int start = 0;
		for ( start=0; start<p.length && 0x00==p[start]; start++ );
		if ( p.length <= start )
		{
			return false;
		}
		
		return ( id == p[start] );
	}
	
	/**
	 * Does 'p' represent an EC point in uncompressed form
	 * (its first non-zero byte must be equal to 4)?
	 * 
	 * @param p - blob representing an EC point
	 * 
	 * @return true/false
	 */
	public static boolean isUncompreesedPoint(byte[] p)
	{
		return startsWith(p, ECPOINT_UNCOMPRESSED_FORM_INDICATOR);
	}
	
	/**
	 * Checks if the public key (actually an EC point) is valid for the
	 * given elliptic curve specifications. This check is useful to prevent
	 * side channel attacks. 
	 * 
	 * The validation process is described in the Section 3.2.2.
	 * Only some basic checks are performed at the moment, additional tests may
	 * appear in the future.
	 * 
	 * Note: right now checks are adapted to the three supported EC specifications,
	 * assuming Fp finite fields only, cofactor (h) equaling 1, etc.
	 * 
	 * @param ec - elliptic curve specifications
	 * @param key - public key (an EC point) to be verified
	 * 
	 * @return true/false, indicating if the point is valid for the given elliptic curve
	 */
	public static boolean validPublicKey(ECParameterSpec ec, ECPoint key)
	{
		// sanity check
		if ( null==ec || null==key )
		{
			return false;
		}
		
		/*
		 * Elliptic Curve Public Key Validation Primitive:
		 * specified in the Section 3.2.2.1
		 */
		
		// key must not be an infinite point
		if ( key.equals(ECPoint.POINT_INFINITY) )
		{
			return false;
		}
		
		// key's coordinates must be integers in interval [0,p-1]
		ECField fp = ec.getCurve().getField();
		// only finite fields Fp are currently supported
		if ( !(fp instanceof ECFieldFp ) )
		{
			return false;
		}
		BigInteger p = ((ECFieldFp) fp).getP();
		
		// check coordinates' values (c)
		// test fails if c<0 or c>=p
		if ( 
				key.getAffineX().compareTo(BigInteger.ZERO) < 0 ||
				key.getAffineX().compareTo(p) >= 0 ||
				key.getAffineY().compareTo(BigInteger.ZERO) <0 ||
				key.getAffineY().compareTo(p) >= 0
			)
		{
			return false;
		}
		
		/*
		 * Currently all supported EC parameters have h (cofactor) set to 1.
		 * in this case it is not necessary to check that nQ == inf.
		 * Hence it will only be checked that h is equal to 1.
		 */

		if ( 0x01 != ec.getCofactor() )
		{
			return false;
		}
		
		//TODO additional tests
		return true;
	}
	
	/**
	 * Checks if the public key (actually an EC point) is valid for the
	 * given elliptic curve specifications, belonging to alg. This check is 
	 * useful to prevent side channel attacks. 
	 * 
	 * The validation process is described in the Section 3.2.2.
	 * Only some basic checks are performed at the moment, additional tests may
	 * appear in the future.
	 * 
	 * @param alg - key type
	 * @param key - public key (an EC point) to be verified
	 * 
	 * @return true/false, indicating if the point is valid for the given elliptic curve
	 */
	public static boolean validPublicKey(AsymmetricAlgorithm alg, ECPoint key)
	{
		// sanity check
		if ( null == alg )
		{
			return false;
		}
		
		// get the appropriate EC specifications...
		ECParameterSpec spec = getSpec(alg);
		if ( null == spec )
		{
			return false;
		}
		
		// ... and pass it to the more general function
		return validPublicKey(spec, key);
	}
	
	
	/*
	 * Specifications for all three currently supported EC types:
	 * nistp256, nistp384 and nistp521. All values are copied from
	 * SEC 2, Standards for Efficient Cryptography Group,
     * "Recommended Elliptic Curve Domain Parameters"
     * also available at: http://www.secg.org/download/aid-386/sec2_final.pdf
	 */

	// nistp256 a.k.a. "secp256r1" is defined in the section 2.7.2:
	private static final ECParameterSpec EC_NISTP256 = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(octetStringToInteger(ByteHex.toBytes(
				("FF:FF:FF:FF:00:00:00:01:00:00:00:00:00:00:00:00:" +
			     "00:00:00:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF").toCharArray() )) ),  // p  (finite field)
			octetStringToInteger(ByteHex.toBytes(
				("FF:FF:FF:FF:00:00:00:01:00:00:00:00:00:00:00:00:" +
				 "00:00:00:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FC").toCharArray() )), // a  (parameter of the EC)
			octetStringToInteger(ByteHex.toBytes(
				("5A:C6:35:D8:AA:3A:93:E7:B3:EB:BD:55:76:98:86:BC:" +
				 "65:1D:06:B0:CC:53:B0:F6:3B:CE:3C:3E:27:D2:60:4B").toCharArray() ))  // b  (parameter of the EC)
		),  // EllipticCurve
		octetStringToEcPoint(AsymmetricAlgorithm.ECDSA_NISTP256, ByteHex.toBytes(
			("04:6B:17:D1:F2:E1:2C:42:47:F8:BC:E6:E5:63:A4:40:F2:" +
			    "77:03:7D:81:2D:EB:33:A0:F4:A1:39:45:D8:98:C2:96:" +
				"4F:E3:42:E2:FE:1A:7F:9B:8E:E7:EB:4A:7C:0F:9E:16:" + 
			    "2B:CE:33:57:6B:31:5E:CE:CB:B6:40:68:37:BF:51:F5").toCharArray() )),   // G (base point; uncompressed form)
		octetStringToInteger(ByteHex.toBytes(
			("FF:FF:FF:FF:00:00:00:00:FF:FF:FF:FF:FF:FF:FF:FF:" +
			 "BC:E6:FA:AD:A7:17:9E:84:F3:B9:CA:C2:FC:63:25:51").toCharArray())),  // n   (order)
		0x01		// h  (cofactor)
		);  // ECParameterSpec
		
	// nistp384 a.k.a. "secp384r1" is defined in the section 2.8.1:
	private static final ECParameterSpec EC_NISTP384 = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(octetStringToInteger(ByteHex.toBytes(
				("FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
		         "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FE:" + 
			     "FF:FF:FF:FF:00:00:00:00:00:00:00:00:FF:FF:FF:FF").toCharArray() )) ),  // p  (finite field)
			octetStringToInteger(ByteHex.toBytes(
				("FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
		         "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FE:" +
			     "FF:FF:FF:FF:00:00:00:00:00:00:00:00:FF:FF:FF:FC").toCharArray() )), // a  (parameter of the EC)
			octetStringToInteger(ByteHex.toBytes(
				("B3:31:2F:A7:E2:3E:E7:E4:98:8E:05:6B:E3:F8:2D:19:" + 
			     "18:1D:9C:6E:FE:81:41:12:03:14:08:8F:50:13:87:5A:" +
			     "C6:56:39:8D:8A:2E:D1:9D:2A:85:C8:ED:D3:EC:2A:EF").toCharArray() ))  // b  (parameter of the EC)
		),  // EllipticCurve
	    octetStringToEcPoint(AsymmetricAlgorithm.ECDSA_NISTP384, ByteHex.toBytes(
		    ("04:AA:87:CA:22:BE:8B:05:37:8E:B1:C7:1E:F3:20:AD:74:" +
	            "6E:1D:3B:62:8B:A7:9B:98:59:F7:41:E0:82:54:2A:38:" + 
			    "55:02:F2:5D:BF:55:29:6C:3A:54:5E:38:72:76:0A:B7:" +
	            "36:17:DE:4A:96:26:2C:6F:5D:9E:98:BF:92:92:DC:29:" + 
				"F8:F4:1D:BD:28:9A:14:7C:E9:DA:31:13:B5:F0:B8:C0:" +
                "0A:60:B1:CE:1D:7E:81:9D:7A:43:1D:7C:90:EA:0E:5F").toCharArray() )),  // G (base point; uncompressed form)     
        octetStringToInteger(ByteHex.toBytes(
	        ("FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
	 		 "FF:FF:FF:FF:FF:FF:FF:FF:C7:63:4D:81:F4:37:2D:DF:" + 
			 "58:1A:0D:B2:48:B0:A7:7A:EC:EC:19:6A:CC:C5:29:73").toCharArray())),  // n   (order)
		0x01		// h  (cofactor)
		);  // ECParameterSpec
	
	// nistp521 a.k.a. "secp521r1" is defined in the section 2.9.1:
	private static final ECParameterSpec EC_NISTP521 = new ECParameterSpec(
		new EllipticCurve(
			new ECFieldFp(octetStringToInteger(ByteHex.toBytes(
				("01:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" + 
				       "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
					   "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
				       "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF").toCharArray() )) ),  // p  (finite field)
			octetStringToInteger(ByteHex.toBytes(
				("01:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" + 
				       "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
				       "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
				       "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FC").toCharArray() )), // a  (parameter of the EC)
			octetStringToInteger(ByteHex.toBytes(
				("00:51:95:3E:B9:61:8E:1C:9A:1F:92:9A:21:A0:B6:85:40:EE:" +
				       "A2:DA:72:5B:99:B3:15:F3:B8:B4:89:91:8E:F1:09:E1:" +
				       "56:19:39:51:EC:7E:93:7B:16:52:C0:BD:3B:B1:BF:07:" +
				       "35:73:DF:88:3D:2C:34:F1:EF:45:1F:D4:6B:50:3F:00").toCharArray() ))  // b  (parameter of the EC)
		 ),  // EllipticCurve
		octetStringToEcPoint(AsymmetricAlgorithm.ECDSA_NISTP521, ByteHex.toBytes(
			("04:00:C6:85:8E:06:B7:04:04:E9:CD:9E:3E:CB:66:23:95:" + 
		        "B4:42:9C:64:81:39:05:3F:B5:21:F8:28:AF:60:6B:4D:" +
			    "3D:BA:A1:4B:5E:77:EF:E7:59:28:FE:1D:C1:27:A2:FF:" +
			    "A8:DE:33:48:B3:C1:85:6A:42:9B:F9:7E:7E:31:C2:E5:" +
			    "BD:66:01:18:39:29:6A:78:9A:3B:C0:04:5C:8A:5F:B4:" +
			    "2C:7D:1B:D9:98:F5:44:49:57:9B:44:68:17:AF:BD:17:" +
			    "27:3E:66:2C:97:EE:72:99:5E:F4:26:40:C5:50:B9:01:" +
			    "3F:AD:07:61:35:3C:70:86:A2:72:C2:40:88:BE:94:76:" + 
			    "9F:D1:66:50").toCharArray() )),  // G (base point; uncompressed form)
		octetStringToInteger(ByteHex.toBytes(
			("01:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:" +
		           "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FA:" + 
				   "51:86:87:83:BF:2F:96:6B:7F:CC:01:48:F7:09:A5:D0:" +
		           "3B:B5:C9:B8:89:9C:47:AE:BB:6F:B7:1E:91:38:64:09").toCharArray())),  // n   (order)
		0x01		// h  (cofactor)
		);
		
}
