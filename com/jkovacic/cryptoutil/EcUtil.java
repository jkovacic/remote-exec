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
	
	// internal static variables for specifications of supported EC types:
	private static final ECParameterSpec EC_NISTP256;
	private static final ECParameterSpec EC_NISTP384;
	private static final ECParameterSpec EC_NISTP521;
	
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
	 * A static initialization block that initializes internal variables
	 * EC_NISTP256, EC_NISTP384 and EC_NISTP521. The block is executed when
	 * the class is loaded.
	 * 
	 * Specifications for all three currently supported EC types:
	 * nistp256, nistp384 and nistp521. All values are copied from
	 * SEC 2, Standards for Efficient Cryptography Group,
     * "Recommended Elliptic Curve Domain Parameters"
     * also available at: http://www.secg.org/download/aid-386/sec2_final.pdf
	 */
	
	static
	{
		// First define values (byte arrays) for all supported EC types,
		// such as p, a, b, G, n, h
		
		// Common co-factor for all EC specifications:
		final int COFACTOR = 0x01;
		
		/*
		 * 
		 * nistp256 a.k.a. "secp256r1" is defined in the section 2.7.2:
		 * 
		 */
		
		/*
		 * Finite field (P):
		 * FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
		 */
		final byte[] EC_NISTP256_P = {
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, 
		    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
		    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF 
		};
				
		/*
		 * Parameter a of the EC:
		 * FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC
		 */
		final byte[] EC_NISTP256_A = {
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, 
		    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
		    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC 
		};
		
		/*
		 * Parameter b of the EC:
		 * 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
		 */
		final byte[] EC_NISTP256_B = {
		    (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7, 
		    (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC, 
		    (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6, 
		    (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B 
		};
		
		/*
		 * Base point (G) in uncompressed form:
		 * 04 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296 
		 *    4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
		 */
		final byte[] EC_NISTP256_G = {
		    (byte) 0x04, 
		    (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, 
	        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, 
			(byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0, 
			(byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96, 
			(byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, 
			(byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, 
			(byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE, 
			(byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5 
		};
		
		/*
		 * Order of G (N):
		 * FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
		 */
		final byte[] EC_NISTP256_N = {
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84, 
		    (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51 
		};
		
		/*
		 * 
		 * nistp384 a.k.a. "secp384r1" is defined in the section 2.8.1:
		 * 
		 */
		
		/*
		 * Finite field (P):
		 * FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 
		 * FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF
		 */
		final byte[] EC_NISTP384_P = {
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
		    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
		};
		
		/*
		 * Parameter a of the EC:
		 * FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 
		 * FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC
		 */
		final byte[] EC_NISTP384_A = {
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
		    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
		};
		
		/*
		 * Parameter b of the EC:
		 * B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 
		 * 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF
		 */
		final byte[] EC_NISTP384_B = {
		    (byte) 0xB3, (byte) 0x31, (byte) 0x2F, (byte) 0xA7, (byte) 0xE2, (byte) 0x3E, (byte) 0xE7, (byte) 0xE4, 
		    (byte) 0x98, (byte) 0x8E, (byte) 0x05, (byte) 0x6B, (byte) 0xE3, (byte) 0xF8, (byte) 0x2D, (byte) 0x19, 
		    (byte) 0x18, (byte) 0x1D, (byte) 0x9C, (byte) 0x6E, (byte) 0xFE, (byte) 0x81, (byte) 0x41, (byte) 0x12, 
		    (byte) 0x03, (byte) 0x14, (byte) 0x08, (byte) 0x8F, (byte) 0x50, (byte) 0x13, (byte) 0x87, (byte) 0x5A, 
		    (byte) 0xC6, (byte) 0x56, (byte) 0x39, (byte) 0x8D, (byte) 0x8A, (byte) 0x2E, (byte) 0xD1, (byte) 0x9D, 
		    (byte) 0x2A, (byte) 0x85, (byte) 0xC8, (byte) 0xED, (byte) 0xD3, (byte) 0xEC, (byte) 0x2A, (byte) 0xEF
		};
		
		/*
		 * Base point (G) in uncompressed form:
		 * 04 AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38 
		 *    5502F25D BF55296C 3A545E38 72760AB7 3617DE4A 96262C6F 5D9E98BF 9292DC29
		 *    F8F41DBD 289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F
		 */
		final byte[] EC_NISTP384_G = {
		    (byte) 0x04, 
		    (byte) 0xAA, (byte) 0x87, (byte) 0xCA, (byte) 0x22, (byte) 0xBE, (byte) 0x8B, (byte) 0x05, (byte) 0x37, 
		    (byte) 0x8E, (byte) 0xB1, (byte) 0xC7, (byte) 0x1E, (byte) 0xF3, (byte) 0x20, (byte) 0xAD, (byte) 0x74, 
		    (byte) 0x6E, (byte) 0x1D, (byte) 0x3B, (byte) 0x62, (byte) 0x8B, (byte) 0xA7, (byte) 0x9B, (byte) 0x98, 
		    (byte) 0x59, (byte) 0xF7, (byte) 0x41, (byte) 0xE0, (byte) 0x82, (byte) 0x54, (byte) 0x2A, (byte) 0x38, 
		    (byte) 0x55, (byte) 0x02, (byte) 0xF2, (byte) 0x5D, (byte) 0xBF, (byte) 0x55, (byte) 0x29, (byte) 0x6C, 
		    (byte) 0x3A, (byte) 0x54, (byte) 0x5E, (byte) 0x38, (byte) 0x72, (byte) 0x76, (byte) 0x0A, (byte) 0xB7, 
		    (byte) 0x36, (byte) 0x17, (byte) 0xDE, (byte) 0x4A, (byte) 0x96, (byte) 0x26, (byte) 0x2C, (byte) 0x6F, 
		    (byte) 0x5D, (byte) 0x9E, (byte) 0x98, (byte) 0xBF, (byte) 0x92, (byte) 0x92, (byte) 0xDC, (byte) 0x29, 
		    (byte) 0xF8, (byte) 0xF4, (byte) 0x1D, (byte) 0xBD, (byte) 0x28, (byte) 0x9A, (byte) 0x14, (byte) 0x7C, 
		    (byte) 0xE9, (byte) 0xDA, (byte) 0x31, (byte) 0x13, (byte) 0xB5, (byte) 0xF0, (byte) 0xB8, (byte) 0xC0, 
		    (byte) 0x0A, (byte) 0x60, (byte) 0xB1, (byte) 0xCE, (byte) 0x1D, (byte) 0x7E, (byte) 0x81, (byte) 0x9D, 
		    (byte) 0x7A, (byte) 0x43, (byte) 0x1D, (byte) 0x7C, (byte) 0x90, (byte) 0xEA, (byte) 0x0E, (byte) 0x5F
		};	
		
		/*
		 * Order of G (N):
		 * FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
		 * C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973
		 */
		final byte[] EC_NISTP384_N = {
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xC7, (byte) 0x63, (byte) 0x4D, (byte) 0x81, (byte) 0xF4, (byte) 0x37, (byte) 0x2D, (byte) 0xDF, 
		    (byte) 0x58, (byte) 0x1A, (byte) 0x0D, (byte) 0xB2, (byte) 0x48, (byte) 0xB0, (byte) 0xA7, (byte) 0x7A, 
		    (byte) 0xEC, (byte) 0xEC, (byte) 0x19, (byte) 0x6A, (byte) 0xCC, (byte) 0xC5, (byte) 0x29, (byte) 0x73 
		};
		
		/*
		 * 
		 * nistp521 a.k.a. "secp521r1" is defined in the section 2.9.1:
		 * 
		 */
		
		/*
		 * Finite field (P):
		 * 01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 
		 *      FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
		 */
		final byte[] EC_NISTP521_P = {
			(byte) 0x01, (byte) 0xFF,
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF 
		};
				
		/*
		 * Parameter a of the EC:
		 * 01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 
		 *      FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC
		 */
		final byte[] EC_NISTP521_A = {
			(byte) 0x01, (byte) 0xFF,
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC 
		};
		
		/*
		 * Parameter b of the EC:
		 * 0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991 8EF109E1 
		 *      56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4 6B503F00
		 */
		final byte[] EC_NISTP521_B = {
			(byte) 0x00, (byte) 0x51,
		    (byte) 0x95, (byte) 0x3E, (byte) 0xB9, (byte) 0x61, (byte) 0x8E, (byte) 0x1C, (byte) 0x9A, (byte) 0x1F, 
		    (byte) 0x92, (byte) 0x9A, (byte) 0x21, (byte) 0xA0, (byte) 0xB6, (byte) 0x85, (byte) 0x40, (byte) 0xEE, 
		    (byte) 0xA2, (byte) 0xDA, (byte) 0x72, (byte) 0x5B, (byte) 0x99, (byte) 0xB3, (byte) 0x15, (byte) 0xF3, 
		    (byte) 0xB8, (byte) 0xB4, (byte) 0x89, (byte) 0x91, (byte) 0x8E, (byte) 0xF1, (byte) 0x09, (byte) 0xE1, 
		    (byte) 0x56, (byte) 0x19, (byte) 0x39, (byte) 0x51, (byte) 0xEC, (byte) 0x7E, (byte) 0x93, (byte) 0x7B, 
		    (byte) 0x16, (byte) 0x52, (byte) 0xC0, (byte) 0xBD, (byte) 0x3B, (byte) 0xB1, (byte) 0xBF, (byte) 0x07, 
		    (byte) 0x35, (byte) 0x73, (byte) 0xDF, (byte) 0x88, (byte) 0x3D, (byte) 0x2C, (byte) 0x34, (byte) 0xF1, 
		    (byte) 0xEF, (byte) 0x45, (byte) 0x1F, (byte) 0xD4, (byte) 0x6B, (byte) 0x50, (byte) 0x3F, (byte) 0x00
		};
		
		/*
		 * Base point (G) in uncompressed form:
		 * 04 00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F B521F828 AF606B4D 
		 *    3DBAA14B 5E77EFE7 5928FE1D C127A2FF A8DE3348 B3C1856A 429BF97E 7E31C2E5 
		 *    BD660118 39296A78 9A3BC004 5C8A5FB4 2C7D1BD9 98F54449 579B4468 17AFBD17 
		 *    273E662C 97EE7299 5EF42640 C550B901 3FAD0761 353C7086 A272C240 88BE9476 
		 *    9FD16650
		 */
		final byte[] EC_NISTP521_G = {
		    (byte) 0x04, 
		    (byte) 0x00, (byte) 0xC6, (byte) 0x85, (byte) 0x8E, (byte) 0x06, (byte) 0xB7, (byte) 0x04, (byte) 0x04, 
		    (byte) 0xE9, (byte) 0xCD, (byte) 0x9E, (byte) 0x3E, (byte) 0xCB, (byte) 0x66, (byte) 0x23, (byte) 0x95, 
		    (byte) 0xB4, (byte) 0x42, (byte) 0x9C, (byte) 0x64, (byte) 0x81, (byte) 0x39, (byte) 0x05, (byte) 0x3F, 
		    (byte) 0xB5, (byte) 0x21, (byte) 0xF8, (byte) 0x28, (byte) 0xAF, (byte) 0x60, (byte) 0x6B, (byte) 0x4D, 
		    (byte) 0x3D, (byte) 0xBA, (byte) 0xA1, (byte) 0x4B, (byte) 0x5E, (byte) 0x77, (byte) 0xEF, (byte) 0xE7, 
		    (byte) 0x59, (byte) 0x28, (byte) 0xFE, (byte) 0x1D, (byte) 0xC1, (byte) 0x27, (byte) 0xA2, (byte) 0xFF, 
		    (byte) 0xA8, (byte) 0xDE, (byte) 0x33, (byte) 0x48, (byte) 0xB3, (byte) 0xC1, (byte) 0x85, (byte) 0x6A, 
		    (byte) 0x42, (byte) 0x9B, (byte) 0xF9, (byte) 0x7E, (byte) 0x7E, (byte) 0x31, (byte) 0xC2, (byte) 0xE5, 
		    (byte) 0xBD, (byte) 0x66, (byte) 0x01, (byte) 0x18, (byte) 0x39, (byte) 0x29, (byte) 0x6A, (byte) 0x78, 
		    (byte) 0x9A, (byte) 0x3B, (byte) 0xC0, (byte) 0x04, (byte) 0x5C, (byte) 0x8A, (byte) 0x5F, (byte) 0xB4, 
		    (byte) 0x2C, (byte) 0x7D, (byte) 0x1B, (byte) 0xD9, (byte) 0x98, (byte) 0xF5, (byte) 0x44, (byte) 0x49, 
		    (byte) 0x57, (byte) 0x9B, (byte) 0x44, (byte) 0x68, (byte) 0x17, (byte) 0xAF, (byte) 0xBD, (byte) 0x17, 
		    (byte) 0x27, (byte) 0x3E, (byte) 0x66, (byte) 0x2C, (byte) 0x97, (byte) 0xEE, (byte) 0x72, (byte) 0x99, 
		    (byte) 0x5E, (byte) 0xF4, (byte) 0x26, (byte) 0x40, (byte) 0xC5, (byte) 0x50, (byte) 0xB9, (byte) 0x01, 
		    (byte) 0x3F, (byte) 0xAD, (byte) 0x07, (byte) 0x61, (byte) 0x35, (byte) 0x3C, (byte) 0x70, (byte) 0x86, 
		    (byte) 0xA2, (byte) 0x72, (byte) 0xC2, (byte) 0x40, (byte) 0x88, (byte) 0xBE, (byte) 0x94, (byte) 0x76, 
		    (byte) 0x9F, (byte) 0xD1, (byte) 0x66, (byte) 0x50
		};
		
		/*
		 * Order of G (N):
		 * 01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFA
		 *      51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8 899C47AE BB6FB71E 91386409
		 */
		final byte[] EC_NISTP521_N = {
			(byte) 0x01, (byte) 0xFF,
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFA, 
		    (byte) 0x51, (byte) 0x86, (byte) 0x87, (byte) 0x83, (byte) 0xBF, (byte) 0x2F, (byte) 0x96, (byte) 0x6B, 
		    (byte) 0x7F, (byte) 0xCC, (byte) 0x01, (byte) 0x48, (byte) 0xF7, (byte) 0x09, (byte) 0xA5, (byte) 0xD0, 
		    (byte) 0x3B, (byte) 0xB5, (byte) 0xC9, (byte) 0xB8, (byte) 0x89, (byte) 0x9C, (byte) 0x47, (byte) 0xAE, 
		    (byte) 0xBB, (byte) 0x6F, (byte) 0xB7, (byte) 0x1E, (byte) 0x91, (byte) 0x38, (byte) 0x64, (byte) 0x09
		};
			
		// When numeric values have been defined, create specifications of all supported EC types:
			
		// NISTP256:
		EC_NISTP256 = new ECParameterSpec(
			new EllipticCurve(
				new ECFieldFp(octetStringToInteger(EC_NISTP256_P) ),
				octetStringToInteger(EC_NISTP256_A),
				octetStringToInteger(EC_NISTP256_B)  ),
			octetStringToEcPoint(AsymmetricAlgorithm.ECDSA_NISTP256, EC_NISTP256_G),
			octetStringToInteger(EC_NISTP256_N),
			COFACTOR );
			
		// NISTP384:
		EC_NISTP384 = new ECParameterSpec(
			new EllipticCurve(
				new ECFieldFp(octetStringToInteger(EC_NISTP384_P) ),
				octetStringToInteger(EC_NISTP384_A),
				octetStringToInteger(EC_NISTP384_B) ),
		    octetStringToEcPoint(AsymmetricAlgorithm.ECDSA_NISTP384, EC_NISTP384_G),     
	        octetStringToInteger(EC_NISTP384_N),
			COFACTOR );
		
		// NISTP521:
		EC_NISTP521 = new ECParameterSpec(
			new EllipticCurve(
				new ECFieldFp(octetStringToInteger(EC_NISTP521_P) ),
				octetStringToInteger(EC_NISTP521_A),
				octetStringToInteger(EC_NISTP521_B) ),
			octetStringToEcPoint(AsymmetricAlgorithm.ECDSA_NISTP521, EC_NISTP521_G),
			octetStringToInteger(EC_NISTP521_N),
			COFACTOR	);
	}		
}
