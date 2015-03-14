package generateVerify;

import java.security.PrivateKey;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import utils.CertificateNotFoundException;
import utils.CertificateRootFound;
import utils.CertificateVerificationException;
import utils.CertificateVerifier;

public class CAImplementation {

	public static HashMap<X509Certificate, PrivateKey> certDetails = new HashMap<X509Certificate, PrivateKey>();
	public static HashMap<String, HashMap<X509Certificate, PrivateKey>> certificateMap = new HashMap<String, HashMap<X509Certificate, PrivateKey>>();
	public static X509Certificate rootCACertificate;
	public static X509Certificate certificate;
	public static X509Certificate certificatetest;

	public static void generateRoot(String rootCN, String city,
			String organization, String organizationUnit, String state,
			String countryCode, String emailId) throws Exception {
		
		RootCertificateX509 root = new RootCertificateX509(rootCN, city,
				organization, organizationUnit, state, countryCode, emailId);
		root.generateRootX509Certificate();
	}

	public static void generateIntermediate(String CName, String city,
			String organization, String organizationUnit, String state,
			String countryCode, String emailId) throws Exception {
	
		CertificateGenerationX509 generate = new CertificateGenerationX509(CName,
				city, organization, organizationUnit, state, countryCode,
				emailId);

		generate.generateIntermediateX509Certificate(rootCACertificate);
	}

	public static X509Certificate generateClient(X509Certificate issuer, String CName,
			String city, String organization, String organizationUnit,
			String state, String countryCode, String emailId) throws Exception {

		CertificateGenerationX509 generate = new CertificateGenerationX509(
				CName, city, organization, organizationUnit, state,
				countryCode, emailId);

		return generate.generateClientX509Certificate(issuer);
		

	}

	public static boolean verifyCert(String dName) throws CertificateVerificationException,CertificateNotFoundException, CertificateRootFound {
		PKIXCertPathBuilderResult result = null;
		X509Certificate root = null;
		boolean returnValue = false;
		HashMap<X509Certificate, PrivateKey> outer = new HashMap<X509Certificate, PrivateKey>();
		Set<X509Certificate> additionalCerts = new HashSet<X509Certificate>();
		certificatetest = null;

		for (String inter : certificateMap.keySet()) {
			outer = certificateMap.get(inter);
			for (X509Certificate c : outer.keySet()) {
				additionalCerts.add(c);
			}

		}
		for (String inter : certificateMap.keySet()) {
			if (inter.equalsIgnoreCase(dName)) {
				outer = certificateMap.get(inter);
				for (X509Certificate cert : outer.keySet()) {
					certificatetest = cert;
				}
			}
		}
		try {
			if(certificatetest==null)
				throw new CertificateNotFoundException("Not found");
			if(certificatetest.equals(rootCACertificate))
				throw new CertificateRootFound("This is CA");
			 result = CertificateVerifier
					.verifyGeneratedCert(certificatetest, additionalCerts);
			root = result.getTrustAnchor().getTrustedCert();
			returnValue = root.equals(rootCACertificate);
			
		}

		catch (CertificateVerificationException ex) {
			throw ex;
			
		}
		catch(CertificateNotFoundException e){
			throw e;
		}
		catch(CertificateRootFound e){
			throw e;
		}
		return (returnValue);
	}

}
