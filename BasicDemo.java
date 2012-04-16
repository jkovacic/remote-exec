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

import java.util.*;

import com.jkovacic.cli.*;
import com.jkovacic.cryptoutil.*;
import com.jkovacic.ssh2.*;
import com.jkovacic.rclient.*;


/*
 * A class with some basic tests, intended to provide 
 * a brief demonstration of the library.
 */
public class BasicDemo 
{
	// Display command's output and its exit code
	private static void display(CliOutput out)
	{
		System.out.println("Exit code: " + out.getExitCode());
		
		if ( null==out.outStr || out.outStr.length<=0 )
		{
			System.out.println("Nothing on stdout");
		}
		else
		{
			System.out.println("Stdout output:");
			for ( int i=0; i<out.outStr.length; i++ )
			{
				System.out.println(out.outStr[i]);
			}
		}
		
		System.out.println();
		
		if ( null==out.errStr || out.errStr.length<=0 )
		{
			System.out.println("Nothing on stderr");
		}
		else
		{
			System.err.println("Stderr output:");
			for ( int i=0; i<out.errStr.length; i++ )
			{
				System.out.println(out.errStr[i]);
			}
		}
	}
	
	// convert an array of chars to an array of bytes
	public static byte[] chars2bytes(char[] chars)
	{
		if ( null == chars )
		{
			return null;
		}
		
		byte[] ret = new byte[chars.length];
		
		for ( int i=0; i<chars.length; i++ )
		{
			ret[i] = (byte) chars[i];
		}
		
		return ret;
	}
	
	
	public static void main(String[] args)
	{
		/*
		 * The testing environment consisted of two servers: a Windows host with a SSH server
		 * and a Unix host with SSH and rexec enabled. For obvious reasons all data (host names, 
		 * usernames, passwords, keys etc.) are fake and should be replaced by the actual ones.
		 */
		
		try
		{
			// In a real application, the following data should be obtained from a sort of identity
			// management system, in this simple demo they are just hardcoded:
			
			// Windows host:
			String whname = "winhost";
			String wuname = "myusername";
			
			// Base64 format of the eWindows host key 
			char[] winHostkeyB64 = ( 
					"AAAAB3NzaC1kc3MAAACBAP0tzw9S0Ep+DZPByGYwFgSQc9jbJ2nd5ra4Bpf/rtrj1pOEuR1K" +
					"Sywoo1egiusjQCk2nlSFd7+MxTPlxigReTonuF6KV1GBsuRq/KK/MUXIXYK6cCi1fZ6BrPkj" +
					"RjO0zzMsofhaYOaTxWR9jsRKsXjJLwpd3f/d4Ct02MXRAR2JAAAAFQDQsnxBjDebEsmWYZuK" +
					"UzEsyyc6HQAAAIA2ofEOzhpr5Yv0VodBBhmdjoUbuFu+yPIR0HLjmeyfrDHuCRblxA2PMNtR" +
					"oAyEkIOYn5tXyw607KXWRISGezTjtjs/AmZ5dSz4Y1l8PyPfL5eHv5SY6SVdhYCAlIT7XF9K" +
					"5oERXvcIMixO4kcEj2isObbc473uRjw0HeyMldanwQAAAIEA+/aYVf53D8vGJ1Dms3c6M+DG" +
					"UcRyH7122MI9raBv/i0BV1f3HXfRr1pxX0NM/z/MWszEkACtOFR2dspRMsGHSiwoinX5Yk9d" +
					"gLrngrKMIJ3d+yODu3rLt6AsNR5PKprBBEcM88znGuYCGJjJUpLJAzJLnpdTjBUmf6oKoG8q" +
					"hXw="
					).toCharArray();
			
			// converted into array of bytes
			byte[] winPubkey = Base64.decode(winHostkeyB64);
			
			// Public key authentication is enabled on the Windows based SSH server:
			// A fake 1024-bit private key (not used in a real server) is provided here!!!!
			// When testing, the real key (stronger than this one) is copied to this example from a well protected file
	
			// Base64 format of the private key:
		    char[] winPrivKeyB64 = ( 
		    		"MIICWwIBAAKBgQCysE0kXGQs6Bgcwd9rPdFqW8fMJ3QAqc9ZQ6d/F4valPcTvY6K" +
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
		    		"SD9RGSrt7ec7/4l0cjdMSBVH1FJ1tMBU0KC2cvfs1Q==" 
					).toCharArray();
					
		    // converted into an array of bytes
		    byte[] winPrivKey = Base64.decode(winPrivKeyB64);
		    
		    // the initial private key (array of chars) is not needed any more, overwrite it with zeros
		    Arrays.fill(winPrivKeyB64, '\u0000');
		    
			// All data for the Windows host are ready, now pack them into appropriate classes:
		    
		    // Server identification:
		    HostId winHost = new HostId(whname);
			Hostkey winHostkey = new Hostkey(PKAlgs.DSA, winPubkey, Hostkey.HostkeyType.FULL_KEY);
			winHost.insertHostkey(winHostkey);
			
			// User identification (public key authentication will be perforemed):
			UserCredentialsPrivateKey winuser = new UserCredentialsPrivateKey();
			winuser.setUsername(wuname);
			winuser.setMethod(PKAlgs.RSA);
			winuser.setSecret(winPrivKey);
			
			
			// Unix host, password authentication for SSH and rexec:
			String uhname="unixhost";
			String uuname="unixusername";
			// the same password for SSH and rexec:
			char[] upwd = { 'f', 'a', 'k', 'e', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
			
			// A MD5 finger print of the Unix host's public key is provided:
			byte[] uhkey = chars2bytes("22:66:02:d2:b2:23:3b:04:c4:25:9a:7f:4f:d4:30:18".toCharArray());
			
			// All data for the Unix host are ready, now pack them into appropriate classes:
		    
		    // Server identification:
		    HostId uHost = new HostId(uhname);
			Hostkey uHostkey = new Hostkey(PKAlgs.RSA, uhkey, Hostkey.HostkeyType.MD5);
			uHost.insertHostkey(uHostkey);
			
			// User identification (public key authentication will be perforemed):
			UserCredentialsPassword unixuser = new UserCredentialsPassword();
			unixuser.setUsername(uuname);
			unixuser.setSecret(upwd);
			
			// User identification for Rexec:
			RexecCredentials unixr = new RexecCredentials(uhname, uuname, upwd);
			
			
			// SSH parameters for both hosts:
			EncryptionAlgorithms commonalgs = new EncryptionAlgorithms();
			commonalgs.appendCipher(Ciphers.AES128_CBC);
			commonalgs.appendCipher(Ciphers.AES128_CTR);
			commonalgs.appendHmac(Hmacs.SHA1);
			commonalgs.appendHmac(Hmacs.MD5);
			commonalgs.appendKex(KexAlgs.DHG14_SHA1);
			commonalgs.appendKex(KexAlgs.DHGEX_SHA1);
			commonalgs.appendComp(CompAlgs.NONE);
			
			// data structure for commands' outputs
			CliOutput out;
			
			
			/*
			 * All setting classes are prepared, now finally start executing commands 
			 */
			
			// locally (on a local Windows host) run "ipconfig /all" (status of all networking adapters):
			System.out.println("= = = = = = = = =  CliLocal  = = = = = = = = =");
			
			IExec local = CliFactory.getLocal();
			String[] commands = new String[5];
			commands[0] = "ipconfig";
			commands[1] = "/all";
			commands[2] = null;  // all commands past this one will be discarded
			
			// this is not necessary for local execution of commands:
			local.prepare();
			out = local.exec(commands);
			
			// again, this is not necessary for local command execution:
			local.cleanup();
			
			display(out);

			
			
			
			System.out.println("\n\n= = = = = = = = =  CLI over SSH to Windows  = = = = = = = = =");
			// connect via SSH to a Windows host and run "route PRINT" (displays routing tables)
			
			// Note: for JSch, you may pass Ssh2.SshImpl.JSCH instead.
			IExec winssh = CliFactory.getSsh(Ssh2.SshImpl.GANYMED, winHost, winuser, commonalgs);

			// this time, prepare must be called that actually establishes a SSH connection
			winssh.prepare();
			out = winssh.exec("route PRINT");
			display(out);
			// disconnect from the SSH server
			winssh.cleanup();
			
			
			
			System.out.println("\n\n= = = = = = = = =  CLI over SSH to Unix  = = = = = = = = =");
			// Connect via SSH to the Unix host and execute "ifconfig -a" (status of all networking adapters).
			// Note that no env. variable is transferred so the whole path to the command must be provided.
			
			// Note: for Ganymed, you may pass Ssh2.SshImpl.GANYMED instead
			IExec ussh = CliFactory.getSsh(Ssh2.SshImpl.JSCH, uHost, unixuser, commonalgs);
			
			ussh.prepare();
			out = ussh.exec("/sbin/ifconfig -a");
			display(out);
			ussh.cleanup();

			
			
			
			System.out.println("\n\n= = = = = = = = =  CLI over Rexec to Unix  = = = = = = = = =");
			// Connect via Rexec to the Unix host and execute "netstat -nr" (displays routing tables).
			// Note that no env. variable is transferred so the whole path to the command must be provided.
			
			IExec rexec = CliFactory.getRexec(unixr);
			rexec.prepare();
			out = rexec.exec("/usr/bin/netstat -nr");
			rexec.cleanup();
			
			display(out);
			
			System.out.println("\n\n= = = = = = = = =  TESTING COMPLETE  = = = = = = = = =");

			// Unix password not needed anymore, zero it out
			Arrays.fill(upwd, '\u0000');
			
		}
		catch ( Exception ex )
		{
			ex.printStackTrace();
		}

	}
}
