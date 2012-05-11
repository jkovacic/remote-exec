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
 * A class, supposed to interact between SSH libraries' wrapper classes and
 * some functionality of com.jkovacic.cryptoutil, e.g. access to private key generation,
 * key formatting, signature handling, etc. classes.
 * 
 * All functions are static so there is no need to instantiate the class.
 * 
 * @author Jernej Kovacic
 */
public class SshSignerHandler 
{
	/*
	 * When forming an EC signature blob, one element must be the EC domain
	 * identifier (e.g. "nistp256"). Probably the simplest way to get is a
	 * substring of the full public key specification as defined by SSH specifications
	 * and PKAlgs. For that reason, a length of the common prefix to all EC 
	 * definitions is needed.
	 */
	private static int EC_PREFIX_LEN = "ecdsa-sha2-".length();
	
	/*
	 * A utility function that cuts all zero-bytes from the start of the given blob.
	 * If nothing was stripped, the reference of 'orig' is returned, otherwise a
	 * new array is created and its reference is returned.
	 * 
	 * @param orig - array of bytes, leading zeros will be cut from
	 * 
	 * @return a stripped array of bytes
	 */
	private static byte[] stripZeros(byte[] orig)
	{
		// sanity check
		if ( null == orig )
		{
			return null;
		}
		
		// find the first non zero byte
		int start = 0;
		for ( start=0; start<orig.length && orig[start]==(byte) 0; start++ );
		
		if ( 0==start || orig.length==start )
		{
			// nothing to strip, return the 'orig' itself
			return orig;
		}
		
		// create a new array of bytes
		byte[] retVal = new byte[orig.length-start];
		System.arraycopy(orig, start, retVal, 0, retVal.length);
		
		// and return its reference
		return retVal;
	}
	
	/**
	 * Formats the public key as defined by SSH specifications, so it
	 * can be sent to the SSH server. RSA and DSA public key formats are specified
	 * by RFC 4716:  http://tools.ietf.org/html/rfc4716
	 * EC public key formats are specified by RFC 5656: http://tools.ietf.org/html/rfc5656
	 * 
	 * Note that 'dec' must be parsed before passing it to this method
	 * 
	 * @param alg - key type
	 * @param dec - an instance of DerDecoderPrivateKey, holding the key material, parse() must be run on it before passing it to the method
	 * 
	 * @return - SSH formatted public key blob or null in case of an error
	 */
	public static byte[] preparePublic(PKAlgs alg, DerDecoderPrivateKey dec)
	{
		// sanity check
		if ( null==alg || null==dec )
		{
			return null;
		}
		
		if ( false == dec.ready() )
		{
			return null;
		}
						
		// A utility class for preparation of public key blobs
		SshFormatter pubkeyForm = new SshFormatter();
		byte[] retVal = null;
		
		// extract necessary information from dec and compose the key blob
		switch (alg)
		{
		case RSA:
			pubkeyForm.add(alg.getName());
			pubkeyForm.add(dec.get('e'));
			pubkeyForm.add(dec.get('n'));
			retVal = pubkeyForm.format();
			break;
			
		case DSA:
			pubkeyForm.add(alg.getName());
			pubkeyForm.add(dec.get('p'));
			pubkeyForm.add(dec.get('q'));
			pubkeyForm.add(dec.get('g'));
			pubkeyForm.add(dec.get('y'));
			retVal = pubkeyForm.format();
			break;
			
		case ECDSA_NISTP256:
		case ECDSA_NISTP384:
		case ECDSA_NISTP521:
			pubkeyForm.add(alg.getName());
			pubkeyForm.add(alg.getName().substring(EC_PREFIX_LEN));
			byte[] pubKey = stripZeros(dec.get('Q'));
			if ( false == EcUtil.isUncompreesedPoint(pubKey) )
			{
				// only uncompressed form of EC public keys (EC points)
				// is currently supported
				retVal = null;
				break; // out of switch
			}
						
			pubkeyForm.add(pubKey);
			retVal = pubkeyForm.format();
			break;
			
		default:
			// Unsupported encryption algorithm.
			// Nothing really to do here as key has not
			// been prepared anyway, later resulting in authentication failure
			retVal = null;
		}
		
		return retVal;
	}
	
	/**
	 * Extracts the necessary information from the 'dec' and create private keys
	 * (instances of KeyCreator) that will be used by Signer.
	 * 
	 * Note that 'dec' must be parsed before passing it to this method
	 * 
	 * @param alg - key type
	 * @param dec - an instance of DerDecoderPrivateKey, holding the key material, parse() must be run on it before passing it to the method
	 * 
	 * @return - an instance of KeyCreator, holding the private and public keys, or null in case of an error
	 */
	public static KeyCreator preparePrivate(PKAlgs alg, DerDecoderPrivateKey dec)
	{
		// sanity check
		if ( null==alg || null==dec )
		{
			return null;
		}
		
		if ( false == dec.ready() )
		{
			return null;
		}
		
		KeyCreator retVal = null;
		
		// Extract necessary key material out of the DER encoded key and create a KeyCreator
		switch (alg)
		{
		case RSA:
			retVal = KeyCreator.createRSAinstance(
					dec.get('n'), 
					dec.get('e'), 
					dec.get('d') );
			break;
			
		case DSA:
			retVal = KeyCreator.createDSAinstance(
					dec.get('p'), 
					dec.get('q'), 
					dec.get('g'), 
					dec.get('y'), 
					dec.get('x') );
			break;
			
		case ECDSA_NISTP256:
		case ECDSA_NISTP384:
		case ECDSA_NISTP521:
			retVal = KeyCreator.createECinstance(
					alg.toCU(), 
					dec.get('Q'), 
					dec.get('d') );
			break;
			
		default:
			// Unsupported encryption algorithm.
			// Nothing really to do here as keys have not
			// been prepared anyway, later resulting in authentication failure
			retVal = null;
		}
		
		return retVal;
	}
	
	/**
	 * A convenience method to create a digital signature. The method will automatically
	 * assign the correct digest algorithm as specified by SSH standards.
	 * 
	 * @param key - private key to use for the signature
	 * @param blob - message to be signed
	 * 
	 * @return
	 */
	public static byte[] getSignature(KeyCreator key, byte[] blob)
	{
		// sanity check
		if ( null==key || null==blob )
		{
			return null;
		}
		
		byte[] retVal = null;
		try
		{
			// Prepare a signature using Signer
			DigestAlgorithm hash = null;
			
			// the actual digest algorithm depends on the key type
			// as specified by SSH standards
			switch (key.getType())
			{
			case DSA:
			case RSA:
				hash = DigestAlgorithm.SHA1;
				break;
				
			case ECDSA_NISTP256:
				hash = DigestAlgorithm.SHA256;
				break;
				
			case ECDSA_NISTP384:
				hash = DigestAlgorithm.SHA384;
				break;
				
			case ECDSA_NISTP521:
				hash = DigestAlgorithm.SHA512;
				break;
				
			default:
				// unsupported
				return null;
			}
			
			// Crypto algorithms and keys are specified,
			// now create a signature
			Signer sig = Signer.getInstance(hash);
			sig.passKey(key);
			sig.sign(blob);
			
			if ( false == sig.signatureReady() )
			{
				// if signing was unsuccessful just return null (i.e. no signature)
				// which will result in an authentication failure
				return null;
			}
			
			// Prepare a signature blob as required by theSSH standard: RFC 4253, Section 6.6:
			// http://tools.ietf.org/html/rfc4253#section-6.6
			
			// regardless of the key type, the blob will start with the algorithm name
			SshFormatter form = new SshFormatter();
			form.add(PKAlgs.fromGeneral(key.getType()).getName());
			
			switch (key.getType())
			{
			case RSA:
				// RSA signature format is already SSH standard compliant
				// so no conversion is necessary
				form.add(sig.getSignature());
				break;
				
			case DSA:
			{
				// DSA signature format, returned by Java cryptography providers (and Signer),
				// is ASN.1. However, SSH standard requires it to be converted to IEEE P1363 format.
				// This is implemented by DsaSignatureAdapter.
				DsaSignatureAdapter conv = new DsaSignatureAdapter(sig.getSignature());
				conv.convert();
				// if signing failed, null will be returned, later resulting in an authentication failure
				form.add(conv.getSshSignature());
				break;
			}
			
			case ECDSA_NISTP256:
			case ECDSA_NISTP384:
			case ECDSA_NISTP521:
			{
				// ECDSA signature format is defined in EFC5656, Section 3:
				// http://tools.ietf.org/html/rfc5656#section-3
				// Java crypto providers return it in ASN.1 format, so it is
				// necessary to convert it into the appropriate format:
				EcdsaSignatureAdapter conv = new EcdsaSignatureAdapter(sig.getSignature());
				conv.convert();
				
				// As defined by the standard, a SSH formatted sub-blob must be created first,
				// containing mpint(r) and mpint(s)
				SshFormatter sigBlob = new SshFormatter();
				sigBlob.add(conv.getR());
				sigBlob.add(conv.getS());
				
				// Then this sub-blob must be SSH formatted and appended to the
				// final signature blob:
				form.add(sigBlob.format());
				break;
			}
			
			default:
				// unsupported key type, return null which will later result in
				// an authentication failure.
				return null;
				
			}
			
			// Signing and (possibly) conversion were successful, format the signature blob
			retVal = form.format();
		}
		catch ( SignerException ex )
		{
			retVal = null;
		}
		
		return retVal;
	}
}
