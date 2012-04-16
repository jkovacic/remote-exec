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

import java.security.*;


/**
 * Implementation of a digital signature, based on a hash and private key cryptography.
 * It may be handy to implement a SSH key agent.
 * 
 * The implemented procedure is stateful, so the methods must be called in the correct order,
 * as described below:
 * 
 * - Instantiate a class using the getInstance() factory. Digest algorithm must be specified at this time.
 * - Assign private and public keys by generating an instance of KeyCreator and pass it to passKey(). 
 * - Keys can be reassigned, even to a different encryption algorithm. 
 * - Check readiness of keys by calling keyReady(). Information of keys are available via getKeyPair()
 * - When keys are ready, data can be passed by calling sign().
 * - Check success of signing by calling signatureReady()
 * - If the signature process is successful, the signature is available by calling getSignature() 
 * 
 * @author Jernej Kovacic
 */
public class Signer 
{
	// internal state of the signing process
	private SignerState state = SignerState.UNINITIALIZED;
	
	// asymmetric key pair handling class	
	private KeyCreator kc = null;
	
	// digest algorithm for the digital signature
	private DigestAlgorithm hashtype = null;
	
	// The digital signature
	private byte[] signature;
	
	/*
	 * Constructor
	 * 
	 * Creates an instance of the class, using the specified hashing algorithm.
	 * Public key algorithm will be specified later, together with the keys themselves
	 *  
	 * @param hashalg - hashing algorithm
	 */
	private Signer(DigestAlgorithm hashalg)
	{
		this.hashtype = hashalg;
		
		this.state = SignerState.UNINITIALIZED;
		this.signature = null;
	}
	
	/**
	 * A factory that instantiates an instance of this class and specifies
	 * the digest algorithm. At the moment only SHA-1 is supported
	 * 
	 * @param hashalg - digest algorithm
	 * 
	 * @return an instance of this class
	 * 
	 * @throws SignerException in case of an unspecified or unsupported digest algorithm
	 */
	public static Signer getInstance(DigestAlgorithm hashalg) throws SignerException
	{
		// is the digest algorithm specified?
		if ( null==hashalg)
		{
			throw new SignerException("Unpecified signature algorithms");
		}
		
		// is it among supported ones? (currently only SHA-1 is supported)
		if ( DigestAlgorithm.SHA1 != hashalg )
		{
			throw new SignerException("Unsupported signature algorithms");
		}
		
		return new Signer(hashalg);
	}
	
	/**
	 * Sets a key pair by passing an instance of KeyCreator
	 * 
	 * @param kc - instance of KeyCreator
	 * 
	 * @throws SignerException if kc not specified
	 */
	public void passKey(KeyCreator kc) throws SignerException
	{
		if ( null==kc )
		{
			throw new SignerException("Key nort specified");
		}
		
		this.kc = kc;
		
		// update the state
		state = SignerState.KEYS_GENERATED;
	}
		
	/**
	 * Returns the key pair as a reference to KeyCreator.
	 * 
	 * @return key pair
	 * 
	 * @throws SignerException if the key is not ready
	 */
	public KeyCreator getKeypair() throws SignerException
	{
		// Is the key ready?
		if ( state.getValue() < SignerState.KEYS_GENERATED.getValue() )
		{
			throw new SignerException("Key not generated yet");
		}
		
		return kc;
	}
	
	/**
	 * Digitally signs the given message using 
	 * previously specified encryption algorithms and keys
	 * 
	 * @param data - message to be signed
	 * 
	 * @throws SignerException if keys are not ready or combination of algorithms is not supported
	 */
	public void sign(byte[] data) throws SignerException
	{		
		// Is the private key ready?
		if ( state.getValue() < SignerState.KEYS_GENERATED.getValue() )
		{
			throw new SignerException("Key not generated yet");
		}
		
		// check of input parameters
		if ( null == data )
		{
			throw new SignerException("Nothing to sign");
		}
		
		// check if combination of algorithms is supported
		// and prepare a definition for the Signature factory
		String siginitspec = null;
		
		// SHA-1 and DSA
		if ( DigestAlgorithm.SHA1==hashtype && AsymmetricAlgorithm.DSA==kc.getType() )
		{
			siginitspec = "SHA1withDSA";
		}
		
		// SHA-1 and RSA
		if ( DigestAlgorithm.SHA1==hashtype && AsymmetricAlgorithm.RSA==kc.getType() )
		{
			siginitspec = "SHA1withRSA";
		}
		
		// other combinations are currently not supported
		if ( null==siginitspec )
		{
			throw new SignerException("Unsupported combination of signature algorithms");
		}
		
		Signature sigctx = null;
		try
		{
			// create an instance of a Signature
			sigctx = Signature.getInstance(siginitspec);
			// assign the private key
			sigctx.initSign(kc.getPrivateKey());
			//sign the message
			sigctx.update(data);
			// if all went well, the signature is now available
			signature = sigctx.sign();
		}
		catch ( NoSuchAlgorithmException ex )
		{
			throw new SignerException("Unsupported combination of signature algorithms");
		}
		catch ( InvalidKeyException ex )
		{
			throw new SignerException("Invalid private key");
		}
		catch ( SignatureException ex )
		{
			throw new SignerException("Signature failed");
		}
		
		// if signing is successful, update the state
		state = SignerState.SIGNATURE_READY;
	}
	
	/**
	 * Gets the digital signature, generated during previous steps
	 * 
	 * @return digital signature
	 * 
	 * @throws SignerException if the digital signature is not available
	 */
	public byte[] getSignature() throws SignerException
	{
		// Is the signature available?
		if ( SignerState.SIGNATURE_READY!=state )
		{
			throw new SignerException("Signature not ready yet");
		}
		
		return signature;
	}
	
	/**
	 * A convenience function to check if public and private keys are ready
	 * 
	 * @return true/false
	 */
	public boolean keyReady()
	{
		return ( state.getValue() >= SignerState.KEYS_GENERATED.getValue() );
	}
	
	/**
	 * A convenience function to check if the digital signature is ready
	 * 
	 * @return true/false
	 */
	public boolean signatureReady()
	{
		return ( state.getValue() == SignerState.SIGNATURE_READY.getValue() );
	}
	
	
	
	/*
	 * An internal enum representing a state of the signing process 
	 * 
	 * @author Jernej Kovacic
	 */
	enum SignerState
	{
		// order of integer values is very important!
		UNINITIALIZED(0),			// object not initialized yet (i.e. keys not generated yet)
		KEYS_GENERATED(1),			// keys have been generated
		SIGNATURE_READY(2);			// signing process is finished, signature is ready to be retrieved
		
		// integer representation of a state, used when checking if the process is in the correct state
		private int sigstate;
		
		/*
		 * Constructor
		 * 
		 * @param stateCode
		 */
		private SignerState(int stateCode)
		{
			this.sigstate = stateCode;
		}
		
		/*
		 * Integer representation of a state
		 * 
		 * @return integer value
		 */
		protected int getValue()
		{
			return sigstate;
		}
	}
}
