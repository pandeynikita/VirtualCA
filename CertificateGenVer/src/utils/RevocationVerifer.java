package utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
public class RevocationVerifer {

	public static void checkRevocationList(X509Certificate cert)
			throws CertificateVerificationException {
		try {
			List<String> crlDistPoints = getCrlDistributionPoints(cert);
			for (String crlcheck : crlDistPoints) {
				X509CRL crl = downloadCRL(crlcheck);
				if (crl.isRevoked(cert)) {
					throw new CertificateVerificationException(
							"The certificate is revoked by CRL: " + crlcheck);
				}
			}
		} catch (Exception e) {
			if (e instanceof CertificateVerificationException) {
				throw (CertificateVerificationException) e;
			} else {
				throw new CertificateVerificationException(
						"Can not verify CRL for certificate: " + 
						cert.getSubjectX500Principal());
			}
		}
	}

	/**
	 * Certification Revocation List is derived from the http, https, ftp, ldap
	 * @param crlURL
	 * @return
	 * @throws IOException
	 * @throws CertificateException
	 * @throws CRLException
	 * @throws CertificateVerificationException
	 * @throws NamingException
	 */
	private static X509CRL downloadCRL(String crlURL) throws IOException,
			CertificateException, CRLException,
			CertificateVerificationException, NamingException {
		if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
				|| crlURL.startsWith("ftp://")) {
			X509CRL crl = getCRLList(crlURL);
			return crl;
		} else if (crlURL.startsWith("ldap://")) {
			X509CRL crl = getCRLfromLdap(crlURL);
			return crl;
		} else {
			throw new CertificateVerificationException(
					"Can not download CRL from certificate " +
					"distribution point: " + crlURL);
		}
	}

	/**
	 * Downloads a CRL from given LDAP url, 
	 */
	private static X509CRL getCRLfromLdap(String ldapURL) 
			throws CertificateException, NamingException, CRLException, 
			CertificateVerificationException {
		Hashtable<String , String> env = new Hashtable<String , String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, 
				"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[])aval.get();
        if ((val == null) || (val.length == 0)) {
        	throw new CertificateVerificationException(
        			"Can not download CRL from: " + ldapURL);
        } else {
        	InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
        	X509CRL crl = (X509CRL)cf.generateCRL(inStream);
        	return crl;
        }
	}
	
	/**
	 * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
	 */
	private static X509CRL getCRLList(String crlURL)
			throws MalformedURLException, IOException, CertificateException,
			CRLException {
		URL url = new URL(crlURL);
		InputStream crlStream = url.openStream();
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
			return crl;
		} finally {
			crlStream.close();
		}
	}

	
	public static List<String> getCrlDistributionPoints(
			X509Certificate cert) throws CertificateParsingException, IOException {
		byte[] crldpExt = cert.getExtensionValue(
				X509Extensions.CRLDistributionPoints.getId());
		if (crldpExt == null) {
			List<String> emptyList = new ArrayList<String>();
			return emptyList;
		}
		@SuppressWarnings("resource")
		ASN1InputStream oAsnInStream = new ASN1InputStream(
				new ByteArrayInputStream(crldpExt));
		DERObject derObjCrlDP = oAsnInStream.readObject();
		DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
		byte[] crldpExtOctets = dosCrlDP.getOctets();
		@SuppressWarnings("resource")
		ASN1InputStream oAsnInStream2 = new ASN1InputStream(
				new ByteArrayInputStream(crldpExtOctets));
		DERObject derObj2 = oAsnInStream2.readObject();
		CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
		List<String> crlList = new ArrayList<String>();
		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                    // Look for an URI
                    for (int j = 0; j < genNames.length; j++) {
                        if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                            crlList.add(url);
                        }
                    }
                }
            }
		}
		return crlList;
	}

}