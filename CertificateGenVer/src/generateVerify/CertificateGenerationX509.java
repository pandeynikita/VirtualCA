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
import org.bouncycastle.jce.X509V1CertificateGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import com.google.common.base.Strings;

public class CertificateGenerationX509 {
	// Certificate Elements
	String commonName, firstName, lastName;
	String city, organization, organizationUnit, state, countryCode, emailId;
	HashMap<X509Certificate, PrivateKey> map;
	public static X509Certificate certificate;

	Date validityStartDate, validityEndDate;
	X509Name dnName, subj;
	// Key Pair Generation
	KeyPair keyPair;

	public CertificateGenerationX509(String commonName, String city,
			String organization, String organizationUnit, String state,
			String countryCode, String emailId) {
		this.commonName = commonName;
		this.city = city;
		this.organization = organization;
		this.organizationUnit = organizationUnit;
		this.state = state;
		this.countryCode = countryCode;
		this.emailId = emailId;
		map = new HashMap<X509Certificate, PrivateKey>();
	}

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public KeyPair generateKeys() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
				"BC");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	@SuppressWarnings("deprecation")
	public void generateIntermediateX509Certificate(X509Certificate rootCert)
			throws Exception {

		X509V3CertificateGenerator generateCert = new X509V3CertificateGenerator();
		certificate = null;
		keyPair = generateKeys();
		// today
		validityStartDate = new Date(System.currentTimeMillis());
		// in 2 years
		validityEndDate = new Date();
		validityEndDate.setDate(validityStartDate.getDate() + 2 * 365);
		dnName = (X509Name) (rootCert.getSubjectDN());
		subj = new X509Name("C=" + countryCode + " ST=" + state + " L=" + city
				+ " O=" + organization + " OU=" + organizationUnit + " CN="
				+ commonName + "/emailAddress=" + emailId);
		generateCert.setSerialNumber(BigInteger.valueOf(System
				.currentTimeMillis()));
		generateCert.setSignatureAlgorithm("md5WithRSAEncryption");
		generateCert.setIssuerDN(dnName);
		generateCert.setNotBefore(validityStartDate);
		generateCert.setNotAfter(validityEndDate);
		generateCert.setSubjectDN(subj);
		generateCert.setPublicKey(keyPair.getPublic());
		generateCert.addExtension(X509Extensions.SubjectKeyIdentifier, false, // not
																				// critical
				new SubjectKeyIdentifierStructure(keyPair.getPublic()));
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign
				| KeyUsage.cRLSign | KeyUsage.digitalSignature
				| KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
				| KeyUsage.nonRepudiation | KeyUsage.keyAgreement);

		// Basic
		BasicConstraints basicConstraint = new BasicConstraints(true);
		generateCert.addExtension(X509Extensions.BasicConstraints.getId(),
				false, basicConstraint);

		generateCert.addExtension(X509Extensions.KeyUsage.getId(), true, // critical
				keyUsage);
		certificate = generateCert
				.generateX509Certificate(CAImplementation.certDetails
						.get(rootCert));

		System.out.println(Strings.repeat("=", 80));
		System.out.println("CERTIFICATE TO_STRING");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		System.out.println(certificate);
		System.out.println();

		System.out.println(Strings.repeat("=", 80));
		System.out
				.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		@SuppressWarnings("resource")
		PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
		pemWriter.writeObject(certificate);
		pemWriter.flush();
		System.out.println();
		System.out.println(Strings.repeat("=", 80));
		System.out
				.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		pemWriter.writeObject(keyPair.getPrivate());
		map.put(certificate, keyPair.getPrivate());
		CAImplementation.certDetails.putAll(map);
		CAImplementation.certificateMap.put(commonName, map);
		pemWriter.flush();

	}

	@SuppressWarnings("deprecation")
	public X509Certificate generateClientX509Certificate(X509Certificate rootCert)
			throws Exception {
		X509V1CertificateGenerator generateCert = new X509V1CertificateGenerator();
		certificate = null;
		keyPair = generateKeys();
		// today
		validityStartDate = new Date(System.currentTimeMillis());
		// in 2 years
		validityEndDate = new Date();
		validityEndDate.setDate(validityStartDate.getDate() + 2 * 365);
		dnName = (X509Name) (rootCert.getSubjectDN());
		subj = new X509Name("C=" + countryCode + " ST=" + state + " L=" + city
				+ " O=" + organization + " OU=" + organizationUnit + " CN="
				+ commonName + "/emailAddress=" + emailId);
		generateCert.setSerialNumber(BigInteger.valueOf(System
				.currentTimeMillis()));
		generateCert.setSignatureAlgorithm("md5WithRSAEncryption");
		generateCert.setIssuerDN(dnName);
		generateCert.setNotBefore(validityStartDate);
		generateCert.setNotAfter(validityEndDate);
		generateCert.setSubjectDN(subj);
		generateCert.setPublicKey(keyPair.getPublic());

		certificate = generateCert
				.generateX509Certificate(CAImplementation.certDetails
						.get(rootCert));

		// DUMP CERTIFICATE AND KEY PAIR
		System.out.println(Strings.repeat("=", 80));
		System.out.println("CERTIFICATE TO_STRING");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		System.out.println(certificate);
		System.out.println();

		System.out.println(Strings.repeat("=", 80));
		System.out
				.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		@SuppressWarnings("resource")
		PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
		pemWriter.writeObject(certificate);
		pemWriter.flush();
		System.out.println();
		System.out.println(Strings.repeat("=", 80));
		System.out
				.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");
		System.out.println(Strings.repeat("=", 80));
		System.out.println();
		pemWriter.writeObject(keyPair.getPrivate());
		map.put(certificate, keyPair.getPrivate());
		CAImplementation.certDetails.putAll(map);
		CAImplementation.certificateMap.put(commonName, map);
		pemWriter.flush();
		return certificate;

	}

}
