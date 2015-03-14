package utils;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

public class CertificateVerifier {

	public static PKIXCertPathBuilderResult verifyGeneratedCert(
			X509Certificate certToVerify, Set<X509Certificate> intermediateCert)
			throws CertificateVerificationException, CertificateRootFound {
		Set<X509Certificate> trustedRootCerts = new HashSet<X509Certificate>();
		Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();
		try {
			if (isRootCert(certToVerify)) {
				throw new CertificateRootFound(
						"This certificate is self-signed. Thus a Root CA");
			}

			for (X509Certificate additionalCert : intermediateCert) {
				if (isRootCert(additionalCert)) {
					trustedRootCerts.add(additionalCert);
				} else {
					intermediateCerts.add(additionalCert);
				}
			}
			PKIXCertPathBuilderResult verifiedCertChain = verifyCertificate(certToVerify, trustedRootCerts, intermediateCerts);
			RevocationVerifer.checkRevocationList(certToVerify);
			return verifiedCertChain;
		} catch (CertPathBuilderException certPathEx) {
			throw new CertificateVerificationException(
					"Error in verification path: "
							+ certToVerify.getSubjectX500Principal(),
					certPathEx);
		} catch (CertificateVerificationException cvex) {
			throw cvex;
		} catch (Exception ex) {
			throw new CertificateVerificationException(
					"Error in verification path: " + certToVerify, ex);
		}
	}

	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	public static boolean isRootCert(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException {
		try {
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		} catch (SignatureException sigEx) {
			return false;
		} catch (InvalidKeyException keyEx) {
			return false;
		}
	}

	private static PKIXCertPathBuilderResult verifyCertificate(
			X509Certificate cert, Set<X509Certificate> trustedRootCerts,
			Set<X509Certificate> intermediateCerts)
			throws GeneralSecurityException {

		// Create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);

		// Create the trust anchors (set of root CA certificates)
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		for (X509Certificate trustedRootCert : trustedRootCerts) {
			trustAnchors.add(new TrustAnchor(trustedRootCert, null));
		}
		// Configure the PKIX certificate builder algorithm parameters
		PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(
				trustAnchors, selector);
		// Disable CRL checks (this is done manually as additional step)
		pkixParams.setRevocationEnabled(false);

		// Specify a list of intermediate certificates
		CertStore intermediateCertStore = CertStore.getInstance("Collection",
				new CollectionCertStoreParameters(intermediateCerts), "BC");
		pkixParams.addCertStore(intermediateCertStore);

		// Build and verify the certification chain
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

		PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder
				.build(pkixParams);
		return result;
	}

}
