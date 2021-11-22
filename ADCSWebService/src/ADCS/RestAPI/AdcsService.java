package ADCS.RestAPI;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.*;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import Util.*;
import sun.misc.BASE64Encoder;
import sun.security.pkcs.PKCS8Key;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import javax.swing.JApplet;
import javax.swing.JOptionPane;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

@Path("/ADCSservice")
public class AdcsService implements Serializable {
	private BCRSAPrivateCrtKey bcrsaPrivateCrtKey;
	private static PKCS10CertificationRequest pkcs10;
	public static String Certificate = "Certificate.cer";
	private static BufferedReader inverifyvault;
	private static final char[] base64m1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			.toCharArray();

	private static final Logger logger = LoggerFactory.getLogger(AdcsService.class);
	@Context
	private HttpServletRequest request;

	private static String SCCLIENT = "SCClient";
	private String RandomReq = generateRandomString();
	private String RandomCer = generateRandomString();
	private String RandomPfx = generateRandomString();
	private File file = new File("C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req");
	private File file1 = new File("C:\\ADCS\\Tomcat\\temp\\" + RandomCer + ".cer");
	private File file2 = new File("C:\\ADCS\\Tomcat\\temp\\" + RandomCer + ".rsp");
	private File file3 = new File("C:\\ADCS\\Tomcat\\temp\\" + RandomPfx + ".pfx");

//	Service: ADCS
//
//	API Version:7.2
//
//	Send certificate sign request to the certificate authority.
//
//	The certificate authority sign and issue the certificate.
//	Examples
//	Sample Request
//	POST http://scrbpkidk003313.crb.apmoller.net:8080/ADCSWebService/ADCSservice/SendCSR
//	Request Body
//
//	{
//	"CertificateTemplate": "RestAPIAPMMSSLCERT",
//	"Domain_Name": "SCRBPKIDK003311.CRB.APMOLLER.NET",
//	"Certificate_Authority_Name": "APMM Corporate Issuing CA 1",
//	"CertificateSignRequest": "-----BEGIN CERTIFICATE REQUEST-----\r\nMIICpjCCAY4CAQAwYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNIMQswCQYDVQQ.........==\r\n-----END CERTIFICATE REQUEST-----\r\n"
//
//	}
//
//	Sample Response
//	{
//	    "ValidFrom": "2021-07-03T20:18:49Z[UTC]",
//	    "ValidUntil": "2023-07-03T20:18:49Z[UTC]",
//	    "Certificate": "-----BEGIN CERTIFICATE-----\nMIIGJDCCBQygAwIBAgITJQAAAajUdhVVdfK2zQAAAAABqDANBgkqhkiG==\r\n-----END CERTIFICATE-----"
//	}

	@POST
	@Path("/SendCSR")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JSONObject generateRequest(JSONObject jsonRequest) throws IOException, InterruptedException,
			NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

		deleteIfExists(file);
		deleteIfExists(file1);
		deleteIfExists(file2);
		deleteIfExists(file3);

		JSONObject generateResponse = new JSONObject();
		try {

			// Set request information
			// Example:
//				Request Body
			//
//					{
//					"CertificateTemplate": "RestAPIAPMMSSLCERT",
//					"Domain_Name": "SCRBPKIDK003311.CRB.APMOLLER.NET",
//					"Certificate_Authority_Name": "APMM Corporate Issuing CA 1",
//					"CertificateSignRequest": "-----BEGIN CERTIFICATE REQUEST-----\r\nMIICpjCCAY4CAQAwYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNIMQswCQYDVQQ.........==\r\n-----END CERTIFICATE REQUEST-----\r\n"
			//
//					}
			String CertificateTemplate = (String) jsonRequest.get("CertificateTemplate");
			logger.info("Certificate Template: " + CertificateTemplate);
			String CSR = (String) jsonRequest.get("CertificateSignRequest");
			logger.info("Certificate Sign Request: " + CSR);

			String fileName = "C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req";
			FileOutputStream fos = new FileOutputStream(fileName);
			try (OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
				osw.write(CSR);
			}
			// Create CertificateFactory Object to Parse X.509 Certificate
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			logger.info("Create Certificate Factory");

			Object lck = new Object();

			try {
// Send the PKCS#10 request to the CA using certreq Microsoft service
				Runtime rt = Runtime.getRuntime();
				String Domain_Name = (String) jsonRequest.get("Domain_Name");
				logger.info("Domain_Name:" + Domain_Name);
				String Certificate_Authority_Name = (String) jsonRequest.get("Certificate_Authority_Name");
				logger.info("Certificate_Authority_Name:" + Certificate_Authority_Name);
				String cmdString3 = "cmd /c certreq -submit -binary -attrib CertificateTemplate:" + CertificateTemplate
						+ " -config " + Domain_Name + "\\\"" + Certificate_Authority_Name
						+ "\" C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req C:\\ADCS\\Tomcat\\temp\\" + RandomCer
						+ ".cer";

				Process pr3 = rt.exec(cmdString3);

				boolean result = pr3.waitFor(10, TimeUnit.SECONDS);
				logger.info("Execute CA request: " + result);

				if (result != true) {
					logger.info("Invalid CA info");
					deleteIfExists(file);
					generateResponse.put("error",
							"Invalid request information, check the validity of the certificate authority, certificate template, domain name, and try again");
				}

				else {

					synchronized (lck) {
						lck.wait(500);
						logger.info("lcl: " + lck);

						FileInputStream in = new FileInputStream("C:\\ADCS\\Tomcat\\temp\\" + RandomCer + ".cer");
						logger.info("1: ");
						// Create certificate Object
						Certificate c = cf.generateCertificate(in);
						logger.info("Certificate: " + c);
						X509Certificate xc = (X509Certificate) c;
						logger.info("Cert:" + xc.getNotAfter());
                        //JSON Response OBJECT (generateResponse)
						generateResponse.put("SerialNumber", xc.getSerialNumber());
						generateResponse.put("ValidFrom", xc.getNotBefore());
						generateResponse.put("ValidUntil", xc.getNotAfter());
                        //Create Base64 Certificate response format
						Base64 encoder = new Base64(64);
						String cert_begin = "-----BEGIN CERTIFICATE-----\n";
						String end_cert = "-----END CERTIFICATE-----";

						byte[] derCert = xc.getEncoded();
						String pemCertPre = new String(encoder.encode(derCert));
						String pemCert = cert_begin + pemCertPre + end_cert;

						generateResponse.put("Certificate", pemCert);
						logger.info("Cert Pem:" + pemCert);
						in.close();
						deleteIfExists(file);
						deleteIfExists(file1);
						deleteIfExists(file2);

					}

				}
			} catch (Exception e) {
				logger.info(e.toString());
				e.printStackTrace();
			}
			return generateResponse;
		} catch (Exception ex) {

			logger.error("Error in Generate Request.", ex);
			return generateResponse;
		}
	}

//	Service: Key Vault/ADCS
//
//	API Version:7.2
//
//	Check if the vault with a specific business application Vault_Name was created.
//
//	Check if Azure_AD_Authorization_Bearer_Token is valid.
//	Examples
//	Sample Request
//	POST http://scrbpkidk003313.crb.apmoller.net:8080/ADCSWebService/ADCSservice/Checkifthevaultexist
//	Request Body
//
//	{
//	    "Vault_Name": "pkikeyvault",
//	    "Azure_AD_Authorization_Bearer_Token": "eeyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I......"
//	}
//
//	Sample Response
//	{
//	    "attributes": {
//	        "recoverableDays": 90,
//	        "created": 1622578227,
//	        "recoveryLevel": "Recoverable+Purgeable",
//	        "updated": 1622578227,
//	        "enabled": true
//	    },
//	    "id": "https://pkikeyvault.vault.azure.net/secrets/ADCS/367df40937de418ca7d61d43d2798d0c",
//	    "value": "ADCS"
//	}
//
//	error
//
//
//
//	{
//	    "error": "Invalid Vault"
//	}

	@POST
	@Path("/Checkifthevaultexist")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JSONObject Checkifthevaultexist(JSONObject jsonRequest)
			throws IOException, InterruptedException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, OperatorCreationException, ParseException {
		//Get Azure_AD_Authorization_Bearer_Token from Json request

		String Azure_AD_Authorization_Bearer_Token = (String) jsonRequest.get("Azure_AD_Authorization_Bearer_Token");
		//Get Vault_Name from Json request
		String Vault_Name = (String) jsonRequest.get("Vault_Name");
		//Create authHeader Object
		String authHeader = String.format("Bearer %s", Azure_AD_Authorization_Bearer_Token);

		String KeyVault_URL = (String) jsonRequest.get("KeyVault_URL");
		URL url = new URL("https://" + Vault_Name + ".vault.azure.net/secrets/ADCS?api-version=7.1");

		HttpURLConnection http = (HttpURLConnection) url.openConnection();
		http.setRequestMethod("GET");
		http.setDoOutput(true);
		http.setRequestProperty("Accept", "application/json");
		http.setRequestProperty("Authorization", authHeader);
		http.setRequestProperty("Content-Type", "application/json");
		http.setConnectTimeout(10000);
		http.setReadTimeout(10000);
		String response = "";
		try {
			inverifyvault = new BufferedReader(new InputStreamReader(http.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block

			JSONObject jsonerror = new JSONObject();
			jsonerror.put("error", "Invalid Vault");
			return jsonerror;
		}
		String line = "";
		while ((line = inverifyvault.readLine()) != null)
			response = response + line;
		inverifyvault.close();
		JSONParser parser = new JSONParser();
		JSONObject json = (JSONObject) parser.parse(response);

		http.disconnect();

		return json;
	}

//	Create PKCS#12/PFX certificate.
//
//	The private key is protected with PFX_Password.
//	Examples
//	Sample Request
//	POST http://scrbpkidk003313.crb.apmoller.net:8080/ADCSWebService/ADCSservice/EnrollPKCS12certificate
//	Request Body
//
//	{
//	    "CN": "Maersk.com",
//	    "EmailAddress": "",
//	    "OU": "OU",
//	    "C": "C",
//	    "ST": "ST",
//	    "O": "O",
//	    "L": "L",
//	    "CertificateTemplate": "RestAPIAPMMSSLCERT",
//	    "Domain_Name": "SCRBPKIDK003311.CRB.APMOLLER.NET",
//	    "PFX_Password": "12345678",
//	    "Certificate_Authority_Name": "APMM Corporate Issuing CA 1"
//	}
//	Sample Response
//	{
//	    "ValidFrom": "2021-07-03T21:35:23Z[UTC]",
//	    "application/x-pkcs12": "MIIM0gIBAzCCDIwGCSqGSIb3DQEHAaCCDH0Eggx5MIIMdTCCBWoGCSqGSIb3DQEHAaCCBVsEggVXMIIFUzCCBU8GCyqGSIA==",
//	    "ValidUntil": "2023-07-03T21:35:23Z[UTC]",
//	    "Certificate": "-----BEGIN CERTIFICATE-----\nMIIGMTCCBRmgAwIBAgITJQAAAamFplMCteugMgAAAAA........----END CERTIFICATE-----"
//	}
	@POST
	@Path("/EnrollPKCS12certificate")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JSONObject EnrollPKCS12certificate(JSONObject jsonRequest)
			throws IOException, InterruptedException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, OperatorCreationException, ParseException {

		logger.info("Start Enroll PKCS12 Certificate");
		
		//Create RSA Key using BouncyCastleProvider lib

		Security.addProvider(new BouncyCastleProvider());
		String sigName = "SHA256withRSA";
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
	    //RSA Key size=2048
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) kp.getPrivate();
		//Create x500NameBld Object to generate PKCS10 file format

		X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
//Get the Subject Name from JSON request
		String CN = (String) jsonRequest.get("CN");
//Check if the CN is empty or not, 
		if (CN.isEmpty()) {

			JSONObject jsoninvalidcommonname = new JSONObject();
			jsoninvalidcommonname.put("error", "The Certificate Common Name cannot be null");
			logger.error("The Certificate Common Name cannot be null");
			return jsoninvalidcommonname;
		} else {

			String C = (String) jsonRequest.get("C");
			String ST = (String) jsonRequest.get("ST");
			String L = (String) jsonRequest.get("L");
			String O = (String) jsonRequest.get("O");
			String OU = (String) jsonRequest.get("OU");
			String EmailAddress = (String) jsonRequest.get("EmailAddress");

			x500NameBld.addRDN(BCStyle.C, C);// 
			x500NameBld.addRDN(BCStyle.ST, ST);
			x500NameBld.addRDN(BCStyle.L, L);
			x500NameBld.addRDN(BCStyle.O, O);
			x500NameBld.addRDN(BCStyle.CN, CN);
			x500NameBld.addRDN(BCStyle.OU, OU);
			x500NameBld.addRDN(BCStyle.EmailAddress, EmailAddress);
			X500Name subject = x500NameBld.build();
			
			//Build PKCS10 (CSR)
			PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
					kp.getPublic());

			logger.info("Certificate subject:" + subject);

			pkcs10 = requestBuilder
					.build(new JcaContentSignerBuilder(sigName).setProvider("BC").build(kp.getPrivate()));
			OutputStream outputpemreq = new FileOutputStream("C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req");
			OutputStreamWriter output = new OutputStreamWriter(outputpemreq);
			PEMWriter pem = new PEMWriter(output);
			pem.writeObject(pkcs10);
			pem.close();

			// End PKCS 10 Proccess

			JSONObject generateResponse = new JSONObject();
			try {

				String CertificateTemplate = (String) jsonRequest.get("CertificateTemplate");
				logger.info("Certificate template:" + CertificateTemplate);

				//Create CertificateFactory object to parse the X.509 certificate
				CertificateFactory cf = CertificateFactory.getInstance("X.509");

				Object lck = new Object();

				try {

					Runtime rt = Runtime.getRuntime();
					String Domain_Name = (String) jsonRequest.get("Domain_Name");
					logger.info("Domain_Name:" + Domain_Name);
					String Certificate_Authority_Name = (String) jsonRequest.get("Certificate_Authority_Name");
					logger.info("Certificate_Authority_Name:" + Certificate_Authority_Name);
					String cmdString3 = "cmd /c certreq -submit -binary -attrib CertificateTemplate:"
							+ CertificateTemplate + " -config " + Domain_Name + "\\\"" + Certificate_Authority_Name
							+ "\" C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req C:\\ADCS\\Tomcat\\temp\\" + RandomCer
							+ ".cer";

					Process pr3 = rt.exec(cmdString3);

					boolean result = pr3.waitFor(10, TimeUnit.SECONDS);
					logger.info("Execute CA request: " + result);

					if (result != true) {
						logger.info("Invalid CA info");
						deleteIfExists(file);
						generateResponse.put("error",
								"Invalid request information, check the validity of the certificate authority, certificate template, domain name, and try again");
					}

					else {

						synchronized (lck) {
							lck.wait(500);

							FileInputStream in = new FileInputStream("C:\\ADCS\\Tomcat\\temp\\" + RandomCer + ".cer");
							Certificate c = cf.generateCertificate(in);

							X509Certificate xc = (X509Certificate) c;
							logger.info("Cert:" + xc.getNotAfter());
							generateResponse.put("ValidFrom", xc.getNotBefore());
							generateResponse.put("ValidUntil", xc.getNotAfter());

							// Convert Certificate To PEM-Base-64 Format
							Base64 encoder = new Base64(64);
							String cert_begin = "-----BEGIN CERTIFICATE-----\n";
							String end_cert = "-----END CERTIFICATE-----";

							byte[] derCert = xc.getEncoded();
							String pemCertPre = new String(encoder.encode(derCert));
							String pemCert = cert_begin + pemCertPre + end_cert;

							generateResponse.put("Certificate", pemCert);
							logger.info("Certificate:" + pemCert);

							in.close();

							// Create PKCS12 file
							FileOutputStream outputStream = new FileOutputStream(
									new File("C:\\ADCS\\Tomcat\\temp\\" + RandomPfx + ".pfx"));
							PKCS12CertificationEnrollment enrollment = new PKCS12CertificationEnrollment("PFXTest",
									outputStream, privateKey);
							enrollment.addCert(xc);
							String PFX_Password = (String) jsonRequest.get("PFX_Password");
							enrollment.enroll(PFX_Password);
							outputStream.close();
							// End PKCS12 creation process

							// Return JSON PFX
							Util util = new Util();
							File filepfx = new File("C:\\ADCS\\Tomcat\\temp\\" + RandomPfx + ".pfx");
							generateResponse.put("application/x-pkcs12", base64Encode(util.readBytesFromFile(filepfx)));
							logger.info("application/x-pkcs12:" + base64Encode(util.readBytesFromFile(filepfx)));

							deleteIfExists(file);
							deleteIfExists(file1);
							deleteIfExists(file2);
							deleteIfExists(file3);

						}
					}
				} catch (Exception e) {
					logger.info(e.toString());
					deleteIfExists(file);
					deleteIfExists(file1);
					deleteIfExists(file2);
					deleteIfExists(file3);

					e.printStackTrace();
				}

				return generateResponse;
			} catch (Exception ex) {
				logger.error("Error in Generate Request.", ex);
				return generateResponse;
			}
		}
	}

//	Service: Key Vault/ADCS
//
//	API Version:7.2
//
//	Create a certificate sign request into a specified key vault.
//
//	Send CSR to ADCS
//	Merge certificate with the associated private key, into Azure Key Vault. The x509 certificate to be imported should be in PEM format. This operation requires certificates/import permission.
//
//	The private key is protected with PFX_Password.
//	Examples
//	Sample Request
//	POST http://scrbpkidk003313.crb.apmoller.net:8080/ADCSWebService/ADCSservice/Enrollcertificate
//	Request Body
//
//	{
//	    "CN": "Maersk.com",
//	    "EmailAddress": "Kamel@Maersk.com",
//	    "OU": "OU",
//	    "C": "C",
//	    "ST": "ST",
//	    "O": "O",
//	    "L": "L",
//	    "CertificateTemplate": "RestAPIAPMMSSLCERT",
//	    "Domain_Name": "SCRBPKIDK003311.CRB.APMOLLER.NET",
//	    "PFX_Password": "12345678",
//	    "Vault_Name": "pkikeyvault",
//	    "Certificate_Authority_Name": "APMM Corporate Issuing CA 1",
//	    "Azure_AD_Authorization_Bearer_Token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I......"
//	}
//
//	Sample Response
//	{
//	    "ValidFrom": "2021-07-03T21:51:06Z[UTC]",
//	    "application/x-pkcs12": "MIIM2gIBAzCCDJQGCSqGSIb3DQEHAaCCDIUEgg.............",
//	    "ValidUntil": "2023-07-03T21:51:06Z[UTC]",
//	    "Certificate": "-----BEGIN CERTIFICATE-----\nMIIGNz...............-----END CERTIFICATE-----"
//	}

	@POST
	@Path("/Enrollcertificate")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JSONObject Enrollcertificate(JSONObject jsonRequest)
			throws IOException, InterruptedException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, OperatorCreationException, ParseException {

		logger.info("Start Enroll Certificate");
		String Azure_AD_Authorization_Bearer_Token = (String) jsonRequest.get("Azure_AD_Authorization_Bearer_Token");
		logger.info("Azure_AD_Authorization_Bearer_Token:" + Azure_AD_Authorization_Bearer_Token);

		String Vault_Name = (String) jsonRequest.get("Vault_Name");
		logger.info("Vault_Name:" + Vault_Name);
		String authHeader = String.format("Bearer %s", Azure_AD_Authorization_Bearer_Token);
		URL url = new URL("https://" + Vault_Name + ".vault.azure.net/secrets/ADCS?api-version=7.1");

		HttpURLConnection http = (HttpURLConnection) url.openConnection();
		http.setRequestMethod("GET");
		http.setDoOutput(true);
		http.setRequestProperty("Accept", "application/json");
		http.setRequestProperty("Authorization", authHeader);
		http.setRequestProperty("Content-Type", "application/json");
		http.setConnectTimeout(10000);
		http.setReadTimeout(10000);
		String response = "";
		try {
			inverifyvault = new BufferedReader(new InputStreamReader(http.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block

			JSONObject jsonerror = new JSONObject();
			jsonerror.put("error", "Invalid Vault Info, Check the Vault Name and Azure Ad Token, and Try Again");
			logger.error("Invalid Vault Info, Check the Vault Name and Azure Ad Token, and Try Again");
			return jsonerror;
		}
		String line = "";
		while ((line = inverifyvault.readLine()) != null)
			response = response + line;
		inverifyvault.close();
		JSONParser parser = new JSONParser();
		JSONObject json = (JSONObject) parser.parse(response);
		http.disconnect();

		deleteIfExists(file);
		deleteIfExists(file1);
		deleteIfExists(file2);
		deleteIfExists(file3);

		Security.addProvider(new BouncyCastleProvider());
		String sigName = "SHA256withRSA";
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) kp.getPrivate();

		X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);

		String CN = (String) jsonRequest.get("CN");

		if (CN.isEmpty()) {

			JSONObject jsoninvalidcommonname = new JSONObject();
			jsoninvalidcommonname.put("error", "The Certificate Common Name cannot be null");
			logger.error("The Certificate Common Name cannot be null");
			return jsoninvalidcommonname;
		} else {

			String C = (String) jsonRequest.get("C");
			String ST = (String) jsonRequest.get("ST");
			String L = (String) jsonRequest.get("L");
			String O = (String) jsonRequest.get("O");
			String OU = (String) jsonRequest.get("OU");
			String EmailAddress = (String) jsonRequest.get("EmailAddress");

			x500NameBld.addRDN(BCStyle.C, C);
			x500NameBld.addRDN(BCStyle.ST, ST);
			x500NameBld.addRDN(BCStyle.L, L);
			x500NameBld.addRDN(BCStyle.O, O);
			x500NameBld.addRDN(BCStyle.CN, CN);
			x500NameBld.addRDN(BCStyle.OU, OU);
			x500NameBld.addRDN(BCStyle.EmailAddress, EmailAddress);
			X500Name subject = x500NameBld.build();
			PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
					kp.getPublic());

			logger.info("Certificate subject:" + subject);

			// PKCS 10 process

			pkcs10 = requestBuilder
					.build(new JcaContentSignerBuilder(sigName).setProvider("BC").build(kp.getPrivate()));
			OutputStream outputpemreq = new FileOutputStream("C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req");
			OutputStreamWriter output = new OutputStreamWriter(outputpemreq);
			PEMWriter pem = new PEMWriter(output);
			pem.writeObject(pkcs10);
			pem.close();

			JSONObject generateResponse = new JSONObject();
			try {

				String CertificateTemplate = (String) jsonRequest.get("CertificateTemplate");
				logger.info("Certificate template:" + CertificateTemplate);

				CertificateFactory cf = CertificateFactory.getInstance("X.509");

				Object lck = new Object();

				try {

					Runtime rt = Runtime.getRuntime();
					String Domain_Name = (String) jsonRequest.get("Domain_Name");
					logger.info("Domain_Name:" + Domain_Name);
					String Certificate_Authority_Name = (String) jsonRequest.get("Certificate_Authority_Name");
					logger.info("Certificate_Authority_Name:" + Certificate_Authority_Name);
					String cmdString3 = "cmd /c certreq -submit -binary -attrib CertificateTemplate:"
							+ CertificateTemplate + " -config " + Domain_Name + "\\\"" + Certificate_Authority_Name
							+ "\" C:\\ADCS\\Tomcat\\temp\\" + RandomReq + ".req C:\\ADCS\\Tomcat\\temp\\" + RandomCer
							+ ".cer";

					Process pr3 = rt.exec(cmdString3);

					boolean result = pr3.waitFor(10, TimeUnit.SECONDS);
					logger.info("Execute CA request: " + result);

					if (result != true) {
						logger.info("Invalid CA info");
						deleteIfExists(file);
						generateResponse.put("error",
								"Invalid request information, check the validity of the certificate authority, certificate template, domain name, and try again");
					}

					else {

						synchronized (lck) {
							lck.wait(500);

							FileInputStream in = new FileInputStream("C:\\ADCS\\Tomcat\\temp\\" + RandomCer + ".cer");
							Certificate c = cf.generateCertificate(in);

							X509Certificate xc = (X509Certificate) c;
							logger.info("Cert:" + xc.getNotAfter());
							generateResponse.put("ValidFrom", xc.getNotBefore());
							generateResponse.put("ValidUntil", xc.getNotAfter());

							// Convert Certificate To PEM-Base-64 format
							Base64 encoder = new Base64(64);
							String cert_begin = "-----BEGIN CERTIFICATE-----\n";
							String end_cert = "-----END CERTIFICATE-----";

							byte[] derCert = xc.getEncoded();
							String pemCertPre = new String(encoder.encode(derCert));
							String pemCert = cert_begin + pemCertPre + end_cert;
							generateResponse.put("Certificate", pemCert);
							logger.info("Certificate:" + pemCert);

							in.close();

							// Create PKCS12 file
							FileOutputStream outputStream = new FileOutputStream(
									new File("C:\\ADCS\\Tomcat\\temp\\" + RandomPfx + ".pfx"));
							PKCS12CertificationEnrollment enrollment = new PKCS12CertificationEnrollment("PFXTest",
									outputStream, privateKey);
							enrollment.addCert(xc);
							String PFX_Password = (String) jsonRequest.get("PFX_Password");
							enrollment.enroll(PFX_Password);
							outputStream.close();

							// Store PFX(PKCS12 File)in Azure KeyVault
							JSONObject jsonObj = new JSONObject();
							JSONObject jsonObj2 = new JSONObject();
							JSONObject jsonObj3 = new JSONObject();
							jsonObj3.put("contentType", "application/x-pkcs12");
							jsonObj2.put("secret_props", jsonObj3);
							jsonObj.put("pwd", PFX_Password);
							jsonObj.put("policy", jsonObj2);

							Util util = new Util();
							File filepfx = new File("C:\\ADCS\\Tomcat\\temp\\" + RandomPfx + ".pfx");

							generateResponse.put("application/x-pkcs12", base64Encode(util.readBytesFromFile(filepfx)));
							logger.info("application/x-pkcs12:" + base64Encode(util.readBytesFromFile(filepfx)));
							jsonObj.put("value", base64Encode(util.readBytesFromFile(filepfx)));
							synchronized (lck) {
			
								lck.wait(1000);

							}

							URL url2 = new URL("https://" + Vault_Name + ".vault.azure.net/certificates/" + CN
									+ "/import?api-version=7.1");
							logger.info("Key Vault POST Request");
							logger.info("https://" + Vault_Name + ".vault.azure.net/certificates/" + CN
									+ "/import?api-version=7.1");
							HttpURLConnection http2 = (HttpURLConnection) url2.openConnection();
							http2.setRequestMethod("POST");
							http2.setDoOutput(true);
							http2.setRequestProperty("Accept", "application/json");
							http2.setRequestProperty("Authorization", authHeader);
							http2.setRequestProperty("Content-Type", "application/json");

							http2.setConnectTimeout(10000);
							http2.setReadTimeout(10000);
							OutputStreamWriter out2 = new OutputStreamWriter(http2.getOutputStream());
							out2.write(jsonObj.toString());
							out2.close();

							BufferedReader in2 = new BufferedReader(new InputStreamReader(http2.getInputStream()));
							String output2;

							StringBuffer response2 = new StringBuffer();
							while ((output2 = in2.readLine()) != null) {
								response2.append(output2);
							}

							in.close();

							http2.disconnect();

							deleteIfExists(file);
							deleteIfExists(file1);
							deleteIfExists(file2);
							deleteIfExists(file3);

						}
					}
				} catch (Exception e) {
					logger.info(e.toString());
					deleteIfExists(file);
					deleteIfExists(file1);
					deleteIfExists(file2);
					deleteIfExists(file3);

					e.printStackTrace();
				}

				return generateResponse;
			} catch (Exception ex) {
				logger.error("Error in Generate Request.", ex);
				return generateResponse;
			}
		}
	}

	public static boolean deleteIfExists(File file) {
		if (file == null) {
			return true;
		}

		return file.delete();
	}

	private String generateRandomString() {

		StringBuilder generatedValue = new StringBuilder();

		final String[] alphaNum = { "A", "B", "C", "D", "E", "W", "X", "Y", "Z", "f", "g", "h", "i", "j", "k", "l", "0",
				"1", "2", "3", "4", "5", "6", "7", "8", "9" };

		int length = alphaNum.length;

		Random r = new Random();
		// 24

		for (int i = 0; i < 10; i++) {

			generatedValue.append(alphaNum[r.nextInt(length)]);

		}

		return generatedValue.toString();

	}

	public static String toHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer(bytes.length * 2);
		for (int i = 0; i < bytes.length; i++) {
			sb.append(toHex(bytes[i] >> 4));
			sb.append(toHex(bytes[i]));
		}

		return sb.toString();
	}

	private static char toHex(int nibble) {
		final char[] hexDigit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		return hexDigit[nibble & 0xF];
	}

	public static String base64Encode(byte[] in) {
		int outLength = (in.length * 4 + 2) / 3; // Output length without padding
		char[] out = new char[((in.length + 2) / 3) * 4]; // Length includes padding.
		int iIn = 0;
		int iOut = 0;
		while (iIn < in.length) {
			int i0 = in[iIn++] & 0xff;
			int i1 = iIn < in.length ? in[iIn++] & 0xff : 0;
			int i2 = iIn < in.length ? in[iIn++] & 0xff : 0;
			int o0 = i0 >>> 2;
			int o1 = ((i0 & 3) << 4) | (i1 >>> 4);
			int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
			int o3 = i2 & 0x3F;
			out[iOut++] = base64m1[o0];
			out[iOut++] = base64m1[o1];
			out[iOut] = iOut < outLength ? base64m1[o2] : '=';
			iOut++;
			out[iOut] = iOut < outLength ? base64m1[o3] : '=';
			iOut++;
		}
		return new String(out);
	}
}
