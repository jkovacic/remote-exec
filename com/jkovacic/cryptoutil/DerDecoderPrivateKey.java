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


/**
 * A specialized class, derived from DerDecoder, used to process
 * DER encoded private key parameters, typically stored (additionally 
 * encoded to Base64) in PEM files by OpenSSH.
 * 
 * Typical procedure to obtain private key parameters from a DER encoded input
 * requires several steps:
 * - instantiate a PrivateKeyDecoder using its constructor and pass it a DER encoded structure
 * - call parse() to start decoding from DER
 * - availability of key parameters may be checked by calling ready()
 * - get individual key parameters by calling get(code). Available code's depend on a key type 
 * 
 * 
 * Format of RSA private keys is explained in RFC 2437:
 * http://tools.ietf.org/html/rfc2437
 * 
 * Format of DSA private keys is explained at OpenSSL site:
 * http://www.openssl.org/docs/apps/dsa.html
 * 
 * Format of ECDSA keys is defined by the standard SEC1, appendix C4:
 * http://www.secg.org/download/aid-780/sec1-v2.pdf
 * 
 * @author Jernej Kovacic
 * 
 * @see DerDecoder
 */
public class DerDecoderPrivateKey extends DerDecoder
{
	/*
	 * EC domain parameter OIDs for three supported EC curves. When EC key
	 * parameters are parsed, these values are checked to confirm that the key
	 * belongs to the right EC curve. OIDs are picked from:
	 *  
	 * SEC 2: Recommended Elliptic Curve Domain Parameters
	 * available at:
	 * http://www.secg.org/download/aid-386/sec2_final.pdf
	 */
	private static final int[] NISTP256_OID = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	private static final int[] NISTP384_OID = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
	private static final int[] NISTP521_OID = { 0x2B, 0x81, 0x04, 0x00, 0x23 };
	
	// is the decoding process completed
	private boolean completed = false;
	
	// private key type (encryption algorithm)
	private AsymmetricAlgorithm keyType = null;
	
	// list of ranges with individual parameters
	private List<SequenceRange> parameters = null;
	
	/**
	 * Constructor.
	 * 
	 * A DER encoded key parameters and asymmetric encryption algorithm must be passed
	 * 
	 * @param type - encryption algorithm
	 * @param blob - DER encoded key parameters, e.g. obtained from a PEM file 
	 */
	public DerDecoderPrivateKey(AsymmetricAlgorithm type, byte[] blob)
	{
		super(blob);
		this.completed = false;
		this.keyType = type;
		// currently supported encryption algorithms have up to 5 parameters,
		// so this is a sensible amount to preallocate
		this.parameters = new ArrayList<SequenceRange>(5);	
	}
		
	/**
	 * Are the key parameters available?
	 * 
	 * @return true/false
	 */
	public boolean ready()
	{
		return completed;
	}
	
	/*
	 * A function to parse DSA key parameters
	 * 
	 * @throws DerException in case of invalid structure
	 */
	private void parseDSA() throws DerException
	{
		// First check the version (must be 0 for DSA)
		SequenceRange verseq = parseInteger();
		
		if ( null==verseq )
		{
			throw new DerException("Version not available");
		}
		
		int version = toInt(verseq);
		if ( 0 != version )
		{
			throw new DerException("Invalid version for DSA key parameter structure");
		}
		
		// Read 5 DSA key parameters as ASN.1 integers and append their ranges to 'parameters'
		SequenceRange par;
		
		// get P, Q, G, Y, and X in that order
		for ( int i=0; i<5; i++ )
		{
			par = parseInteger();
			parameters.add(par);
		}
		
		// The DER structure for DSA private keys may not contain any other data
		if ( true == moreData() )
		{
			throw new DerException("Invalid DSA key parameter structure");
		}
	}
	
	/*
	 * A function to parse RSA key parameters
	 * 
	 * @throws DerException in case of invalid structure
	 */
	private void parseRSA() throws DerException
	{
		// Check the version (must be 0 or 1 for RSA)
		SequenceRange verseq = parseInteger();
		
		if ( null==verseq )
		{
			throw new DerException("Version not available");
		}
		
		int version = toInt(verseq);
		if ( 0!=version && 1!=version ) 
		{
			throw new DerException("Invalid version for RSA key parameter structure");
		}
		
		// Read 3 RSA key parameters as ASN.1 integers  and append their ranges to 'parameters'
		SequenceRange par;
		
		// get N, E and D in that order
		for ( int i=0; i<3; i++ )
		{
			par = parseInteger();
			parameters.add(par);
		}
		
		// RSA private key DER structure contains additional data 
		// (their exact number depends on version) that can
		// optimize key generation. They are not needed by our process so they
		// will not be read and there is no check if the whole sequence has been read
	}
	
	/*
	 * Checks if two OID vectors are equal
	 * 
	 * @param oid - EC domain OID values, parsed from EC key data
	 * 
	 * @param nist - EC domain OID parameters for one of supported EC curves 
	 * 
	 * @return true/false
	 */
	private boolean compareOids(byte[] oid, int[] nist)
	{
		boolean retVal = true;
		
		// if any vector is null, return false
		if ( null==oid || null==nist)
		{
			return false;
		}
		
		// lengths of both vectors must be equal
		if (oid.length != nist.length )
		{
			return false;
		}
		
		// Compare vectors element by element. Note that one vector
		// contains bytes and the other one integers
		for ( int i =0; i<nist.length; i++ )
		{
			if ( oid[i] != (byte) (nist[i] & 0xff) )
			{
				retVal = false;
				// no need to check further
				break;  // out of for i
			}
		}
		
		return retVal;
	}
	
	/*
	 * A function to parse EC key parameters. 
	 * It also checks EC domain parameters.
	 * 
	 * @throws DerException in case of invalid structure
	 */
	private void parseEC() throws DerException
	{
		// First check the version (must be 1 for EC)
		SequenceRange verseq = parseInteger();
				
		if ( null==verseq )
		{
			throw new DerException("Version not available");
		}
		
		int version = toInt(verseq);
		if ( 1 != version )
		{
			throw new DerException("Invalid version for DSA key parameter structure");
		}
		
		SequenceRange seq;
		
		// EC private key, encoded as octet string (must be converted into big int later):
		seq = parseOctetString();
		parameters.add(seq);
		
		// ECDomainParameters is an optional parameter, but OpenSSH's ssh-keygen always creates it
		seq = parseContainer0();
		seq = parseObject();
		// OID values parsed from the ASN.1 object 
		byte[] oid = toByteArray(seq);
		int[] nist = null;
		
		// determine the right vector of OID values to be compared against the 'oid'
		switch (keyType)
		{
		case ECDSA_NISTP256:
			nist = NISTP256_OID;
			break;
			
		case ECDSA_NISTP384:
			nist = NISTP384_OID;
			break;
			
		case ECDSA_NISTP521:
			nist = NISTP521_OID;
			break;
		}
		
		// and finally perform the comparision
		if ( false==compareOids(oid, nist) )
		{
			throw new DerException("Invalid EC domain parameters");
		}
		
		
		// EC public key, encoded as an ASN.1 bit string (must be converted to a pair of big ints later):
		seq = parseContainer1();
		seq = parseBitString();
		parameters.add(seq);
		
		// The DER structure for EC private keys may not contain any other data
		if ( true == moreData() )
		{
			throw new DerException("Invalid EC key parameter structure");
		}
	}
	
	/**
	 * Start parsing of DER structure and prepare key parameters.
	 * If anything fails, key parameters will not be available which 
	 * can be checked by calling ready() 
	 */
	public void parse()
	{
		// if the DER structure has been parsed, there is no need to repeat it the process
		if ( true==completed )
		{
			return;
		}
		
		try
		{
			// first parse initial sequence's header...
			SequenceRange seq = parseSequence();
			if ( null == seq )
			{
				throw new DerException("Invalid initial structure header");
			}
			
			// ...and check that nothing follows the initial sequence
			if ( true==moreData(seq.seqstart + seq.seqlen) )
			{
				throw new DerException("Invalid key parameter data structure");
			}
			
			// start specialized parsing functions, depending on a key type
			switch (keyType)
			{
			case DSA:
				parseDSA();
				break;
				
			case RSA:
				parseRSA();
				break;
				
			case ECDSA_NISTP256:
			case ECDSA_NISTP384:
			case ECDSA_NISTP521:
				parseEC();
				break;
				
			default:
				// unsupported public key type, normally should not occur, 
				// but "handle" it anyway
				throw new DerException("Internal error");
			}
			
			// parsing is complete
			completed = true;
		}
		catch (DerException ex)
		{
			// nothing really to do here, 
			// if any exception occurs, completed will not be set to true,
			// indicating a failure and non-availability of key parameters
		}
	}
	
	/**
	 * Get the requested key parameter. The parameter is specified by 
	 * a character code as explained below:
	 *  
	 * RSA keys:
	 * - N: modulus
	 * - E: public exponent
	 * - D: private exponent
	 * 
	 * DSA keys:
	 * - P: prime
	 * - Q: sub prime 
	 * - G: base
	 * - Y: public key
	 * - X: private key
	 * 
	 * EC keys:
	 * - D or S: private key
	 * - Q or W: public key
	 * 
	 * If key parameters are not available, null will be returned.
	 * 
	 * Note: foe EC keys, the private key is returned as an octet stream and the
	 * public key is returned as a bit string. They must be further converted into 
	 * BigInteger(s) and passed to Java's key factories.
	 *   
	 * @param which - character code (case insensitive) for the key parameter
	 * 
	 * @return - byte array of the requested key parameter or null, if not available or if the code is unknown
	 */
	public byte[] get(char which)
	{
		// Index for the requested parameter in 'parameters'
		int index = -1;
		
		// Are the parameters available?
		if ( false == completed || null == parameters )
		{
			return null;
		}
		
		/*
		 * The right vector of bytes to be returned depends on the char code and
		 * also on the key type (the same char code may be present at several key types).
		 * Nested switch'es are used to ensure better maintainabilty and for better
		 * visibility of all combinations.
		 */
		switch (keyType)
		{
		case RSA:
			switch (which)
			{
			case 'N':
			case 'n':
				index = 0;
				break;
				
			case 'E':
			case 'e':
				index = 1;
				break;
				
			case 'D':
			case 'd':
				index = 2;
				break;
			}
			break;
			
		case DSA:
			switch (which)
			{
			case 'P':
			case 'p':
				index = 0;
				break;
				
			case 'Q':
			case 'q':
				index = 1;
				break;
				
			case 'G':
			case 'g':
				index = 2;
				break;
				
			case 'Y':
			case 'y':
				index = 3;
				break;
				
			case 'X':
			case 'x':
				index = 4;
				break;
			}
			break;
			
		case ECDSA_NISTP256:
		case ECDSA_NISTP384:
		case ECDSA_NISTP521:
			switch (which)
			{
			case 'D':
			case 'd':
			case 'S':
			case 's':
				index = 0;
				break;
				
			case 'Q':
			case 'q':
			case 'W':
			case 'w':
				index = 1;
				break;
			}
			break;
		}
				
		if ( index<0 || index>=parameters.size() )
		{
			return null;
		}
		
		// copy the relevant range to a separate byte array
		byte[] retVal = toByteArray(parameters.get(index));
		
		return retVal;
	}
	
	/*
	 * Key parameter ranges may contain sensitive data, 
	 * hence their data will be reset by the destructor.
	 */
	private void dispose()
	{
		if ( null!=parameters )
		{
			// set all range parameters to zero
			for ( SequenceRange par : parameters )
			{
				par.seqlen = 0;
				par.seqstart = 0;
			}
			
			// and clear the list
			parameters.clear();
		}
	}
	
	/*
	 * Destructor, cleans up key parameter ranges 
	 */
	protected void finalize() throws Throwable 
	{
	    try 
	    {
	    	dispose();
	    } 
	    finally 
	    {
	        super.finalize();
	    }
	}
	
	
	/*
	 * Unit testing function that parses three key structures (one RSA, one for DSA and one for EC)
	 */
	public static void main(String[] args)
	{
		// Fake public keys, generated especially for testing and not used anywhere else
		
		// 1024-bit RSA key
		byte[] rsakey = Base64.decode(
			  ( "MIICWwIBAAKBgQCysE0kXGQs6Bgcwd9rPdFqW8fMJ3QAqc9ZQ6d/F4valPcTvY6K" +
	    		"/8ZmSiPfO0Bua8WF6L8t1ZyQD349xNvcrAGRXvWXibIq7xpL9D2p2LaGTaaz5ySs" +
	    		"ze0ntejPXdhtBPx5UfsctmMgvsk1ipTJ9/frKW4AuqTXzp9WXEr+UXNabwIBEQKB" +
	    		"gBbGJ/MQy4M2rb1kAN37VGprEe9aXJasOw3i+b1f3R5eR6WnN9B17p6bBJJpbx0h" +
	    		"0GPj8DWHJYXPx04lo40Q5xnX1Er7clybMFmSrJDe2svNHVDvCG2RkRaXp2PPtJ0m" +
	    		"+SxzZqkQ/l3QLD7basoazJKMwCm8geQntmC4sn0J9eDhAkEA7AgE2n5xZbE4jDpo" +
	    		"cC5iNiPUW9a/bePDB+oklR1OXHU5vWzt06+2QYxs2kvTJ7jweDXuSlwKpIEIbPey" +
	    		"uDr5XwJBAMHOWg4BMbQVGYa5RuK/vabEPSQfff2XAi961rnPiLHQgFne2Prnnhvh" +
	    		"oGzbsWBwBq+jGbzrMXxf9JTuijdgaPECQQCYueUF2Vhu+jOmB6z9SzB9YnpZivRW" +
	    		"KfaqxK5CXkHDWukgN2y2JmbfHqDJfFt0DkE+uXwR/1IuNV/OCa/gnqFbAkEAqwFe" +
	    		"hNPgj9Zh0ToRXqku3nDqp2cU0LJrVxIIwhF4nOUl9PHOgwiakRJgYA0kCcxCIoDa" +
	    		"eYQ6uQlfVjvjXgnGAQJAXVBei3EAtBxTp0rxWmKcym9D6NGjkPBiTfxB5yiRjASu" +
	    		"SD9RGSrt7ec7/4l0cjdMSBVH1FJ1tMBU0KC2cvfs1Q==" ).toCharArray() 
				);
		
		// 1024-bit DSA key
		byte[] dsakey = Base64.decode(
			  ( "MIIBuwIBAAKBgQCnjx38O84CBZFMsmoFSVEfBDgvs84dq/jrYRl//tz3mczKPC5C" +
				"W1khtjXPoRCWmZBt7gMFYZ0ocwg+M1e+0vy2wcbUzxk1VB/ps0tYLPNNQJR7+K31" +
				"ndZQAiG8rwFZ/jDcOc2FxHBSuYGMhoRgSXUlEp9wy66MI2tE3TGNjOn4uwIVALbe" +
				"syABPOhS1FGzAtswXJgSduBtAoGBAIOvnptwKmdn/co36DOSo8rCqnCxjBVnFq8U" +
				"9P7dkgI/dkWnJR/7yjBKGrKhCSfdRijTHlcY16WnvvB+zCfAPTcL0llrxfRmMpII" +
				"5zrW/YRXi65dONZsM3TFUlUhLKB0Wq1yTiBKYwHAPkV4iImklEvvBkLkO2XsBeMs" +
				"pTVkYqHtAoGAGjgwixZeAJfoaa5n0oe0yVVZuP3Ljbm2oEmfdGvQFnt2gWCubhr1" +
				"kaxvjmY5K+SX0BLaWZB7BnJtIKtJH7jYoYtvvX4FcrTUfkTcyD+RvX+9XdHB3YsW" +
				"gbfujfQ3cB6drBO8/Nm0Pdmn67TZVTfohWWHkf8bDjvdgi9B6Dj3pdMCFAmekjmz" +
				"72jnWwY0r8bi7131ITbE" ).toCharArray()
				);
		
		// EC nistp256 key
		byte[] eckey = Base64.decode(
			  (  "MHcCAQEEIL0iyu/0AkFfyUagMdnY1JqI8SZNCMC+5tTIMsbDVrGFoAoGCCqGSM49" +
				 "AwEHoUQDQgAEWHFOnezz1vnkbhzpyU/wtSpY9DiEtB5BDSOiIWOkngcTnSS67ncd" +
				 "uNVU/DEkTWMIpzvjHFeb6gz5y+Vpaen5Dw==" ).toCharArray()
				);
		
		// initialize one decoder for each key
		DerDecoderPrivateKey rsaengine = new DerDecoderPrivateKey(AsymmetricAlgorithm.RSA, rsakey);
		DerDecoderPrivateKey dsaengine = new DerDecoderPrivateKey(AsymmetricAlgorithm.DSA, dsakey);
		DerDecoderPrivateKey ecengine = new DerDecoderPrivateKey(AsymmetricAlgorithm.ECDSA_NISTP256, eckey);
		
		// start parsing
		rsaengine.parse();
		dsaengine.parse();
		ecengine.parse();
		
		// check success of parsing
		if ( false==rsaengine.ready() )
		{
			System.err.println("RSA parse failed");
			System.exit(-1);
		}
		
		if ( false==dsaengine.ready() )
		{
			System.err.println("DSA parse failed");
			System.exit(-1);
		}
		
		if ( false==ecengine.ready() )
		{
			System.err.println("EC parse failed");
			System.exit(-1);
		}
		
		// and finally display lengths of all parameters
		byte[] n = rsaengine.get('n');
		byte[] e = rsaengine.get('E');
		byte[] d = rsaengine.get('d');
		
		System.out.println("N: " + n.length + " bytes");
		System.out.println("E: " + e.length + " bytes");
		System.out.println("D: " + d.length + " bytes");
		System.out.println();
		
		byte[] p = dsaengine.get('p');
		byte[] q = dsaengine.get('q');
		byte[] g = dsaengine.get('g');
		byte[] y = dsaengine.get('y');
		byte[] x = dsaengine.get('x');
		
		System.out.println("P: " + p.length + " bytes");
		System.out.println("Q: " + q.length + " bytes");
		System.out.println("G: " + g.length + " bytes");
		System.out.println("Y: " + y.length + " bytes");
		System.out.println("X: " + x.length + " bytes");
		System.out.println();
		
		byte[] s = ecengine.get('d');
		byte[] w = ecengine.get('q');
		
		System.out.println("d: " + s.length + " bytes");
		System.out.println("Q: " + w.length + " bytes");
	}
}
