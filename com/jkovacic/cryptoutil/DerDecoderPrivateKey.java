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
 * Format of DSA private keys is evident from the OpenSSH source code,
 * basically also explained at:
 * http://search.cpan.org/~btrott/Convert-PEM-0.08/lib/Convert/PEM.pm
 * 
 * @author Jernej Kovacic
 * 
 * @see DerDecoder
 */
public class DerDecoderPrivateKey extends DerDecoder
{
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
	 * 
	 * If key parameters are not available, null will be returned
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
		
		// The actual ASN.1 integer depends on the code AND on the key type
		// At the moment this is not a case but later, when more key types may be supported,
		// the same code can be used by several key types.
		// Therefore checking of a key type must be done at each case:
		switch (which)
		{
		case 'N':
		case 'n':
			if ( AsymmetricAlgorithm.RSA == keyType )
			{
				index = 0;
			}
			break;
			
		case 'E':
		case 'e':
			if ( AsymmetricAlgorithm.RSA == keyType )
			{
				index = 1;
			}
			break;
			
		case 'D':
		case 'd':
			if ( AsymmetricAlgorithm.RSA == keyType )
			{
				index = 2;
			}
			break;
			
		case 'P':
		case 'p':
			if ( AsymmetricAlgorithm.DSA == keyType )
			{
				index = 0;
			}
			break;
			
		case 'Q':
		case 'q':
			if ( AsymmetricAlgorithm.DSA == keyType )
			{
				index = 1;
			}
			break;
			
		case 'G':
		case 'g':
			if ( AsymmetricAlgorithm.DSA == keyType )
			{
				index = 2;
			}
			break;
			
		case 'Y':
		case 'y':
			if ( AsymmetricAlgorithm.DSA == keyType )
			{
				index = 3;
			}
			break;
			
		case 'X':
		case 'x':
			if ( AsymmetricAlgorithm.DSA == keyType )
			{
				index = 4;
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
	 * Unit testing function that parses two key structures (one RSA and one DSA)
	 */
	public static void main(String[] args)
	{
		// Two fake public keys, generated especially for testing and not used anywhere else
		
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
		
		// initialize one decoder for each key
		DerDecoderPrivateKey rsaengine = new DerDecoderPrivateKey(AsymmetricAlgorithm.RSA, rsakey);
		DerDecoderPrivateKey dsaengine = new DerDecoderPrivateKey(AsymmetricAlgorithm.DSA, dsakey);
		
		// start parsing
		rsaengine.parse();
		dsaengine.parse();
		
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
	}
}
