package Util;

import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;


public class PKCS12CertificationEnrollment {

	private List<X509Certificate> certList;
	private PrivateKey privateKey;
	private String alias;
	private OutputStream output;

	
	public PKCS12CertificationEnrollment(String alias, OutputStream output, PrivateKey privateKey) {
		this.alias = alias;
		this.output = output;
		this.certList = new ArrayList<X509Certificate>();
		this.privateKey = privateKey;
	}


	public int addCert(X509Certificate cert) {
		certList.add(cert);
		return certList.size();
	}


	public void enroll(String pin) {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(null, null);
			ks.setKeyEntry(alias, privateKey, pin.toCharArray(),
					certList.toArray(new Certificate[certList.size()]));
			ks.store(output, pin.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}