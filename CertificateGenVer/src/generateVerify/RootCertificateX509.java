package generateVerify;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import com.google.common.base.Strings;

public class RootCertificateX509 {

	String commonName, firstName, lastName;
	String city, organization, organizationUnit, state, countryCode, emailId;

	HashMap<X509Certificate, PrivateKey> map ;
	public RootCertificateX509(String commonName, String city,
			String organization, String organizationUnit, String state,
			String countryCode, String emailId) {
		this.commonName = commonName;
		this.city = city;
		this.organization = organization;
		this.organizationUnit = organizationUnit;
		this.state = state;
		this.countryCode = countryCode;
		this.emailId = emailId;
		map = new HashMap<X509Certificate, PrivateKey> ();
	
	}
	
	
	static {
		// adds the Bouncy castle provider to java security
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@SuppressWarnings("deprecation")
	public void generateRootX509Certificate() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
				"BC");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// yesterday
		Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60
				* 60 * 1000);
		// in 2 years
		Date validityEndDate = new Date();
		validityEndDate.setDate(validityBeginDate.getDate() + 2 * 365);

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X509Name dnName = new X509Name("C=" + countryCode + " ST=" + state
				+ " L=" + city + " O=" + organization + " OU="
				+ organizationUnit + " CN=" + commonName + "/emailAddress="
				+ emailId);
		X509Name subj = dnName;
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setSignatureAlgorithm("md5WithRSAEncryption");
		certGen.setIssuerDN(dnName); // use the same
		certGen.setNotBefore(validityBeginDate);
		certGen.setNotAfter(validityEndDate);
		certGen.setSubjectDN(subj);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.addExtension(
				X509Extensions.SubjectKeyIdentifier, 
				false, // not critical
				new SubjectKeyIdentifierStructure(keyPair.getPublic())
		);
		KeyUsage keyUsage = new KeyUsage(
				KeyUsage.keyCertSign
				| KeyUsage.cRLSign
				| KeyUsage.digitalSignature
				| KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
				| KeyUsage.nonRepudiation | KeyUsage.keyAgreement  );

		//Basic
		BasicConstraints basicConstraint = new BasicConstraints(true);
		certGen.addExtension(
				X509Extensions.BasicConstraints.getId(),
				false, 
				basicConstraint
		);

		certGen.addExtension(
				X509Extensions.KeyUsage.getId(), 
				true, // critical
				keyUsage
		);
		CAImplementation.rootCACertificate = certGen.generateX509Certificate(keyPair
				.getPrivate());
		// DUMP CERTIFICATE AND KEY PAIR
		System.out.println(Strings.repeat("=", 80));
		System.out.println("CERTIFICATE TO_STRING");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		System.out.println(CAImplementation.rootCACertificate);
		System.out.println();

		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		@SuppressWarnings("resource")
		PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
		pemWriter.writeObject(CAImplementation.rootCACertificate);
		pemWriter.flush();
		System.out.println();
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		pemWriter.writeObject(keyPair.getPrivate());
		map.put(CAImplementation.rootCACertificate, keyPair.getPrivate());
		CAImplementation.certDetails.putAll(map);
		CAImplementation.certificateMap.put(commonName, map);
		pemWriter.flush();
	
	}
	
}
