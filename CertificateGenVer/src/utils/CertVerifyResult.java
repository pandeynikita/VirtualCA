package utils;

import java.security.cert.PKIXCertPathBuilderResult;


public class CertVerifyResult {
	private boolean valid;
	private PKIXCertPathBuilderResult result;
	private Throwable exception;
	
	public CertVerifyResult(
			PKIXCertPathBuilderResult result) {
		this.valid = true;
		this.result = result;
	}

	
	public CertVerifyResult(Throwable exception) {
		this.valid = false;
		this.exception = exception;
	}

	public boolean isValid() {
		return valid;
	}

	public PKIXCertPathBuilderResult getResult() {
		return result;
	}

	public Throwable getException() {
		return exception;
	}	
}
