package com.commonwealthrobotics;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class CompromisedRoots {
	// SHA-256 fingerprints of the roots that chain to the compromised eMudhra
	// intermediate CAs (CVE-2026-111943)
	private static final Set<String> FINGERPRINTS = Set.of(
			"86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b", // emSign ECC Root CA - G3
			"d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"); // AAA Certificate Services
	private static final char[] PASSWORD = "changeit".toCharArray();

	public static void distrustInThisJvm() throws Exception {
		KeyStore trustStore = KeyStore.getInstance(cacerts(new File(System.getProperty("java.home"))), PASSWORD);
		removeFrom(trustStore);
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init(trustStore);
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, factory.getTrustManagers(), null);
		SSLContext.setDefault(context);
	}

	public static void removeFromJvm(File jvmHome) throws Exception {
		File cacerts = cacerts(jvmHome);
		if (!cacerts.exists())
			return;
		KeyStore trustStore = KeyStore.getInstance(cacerts, PASSWORD);
		if (removeFrom(trustStore)) {
			try (OutputStream out = new FileOutputStream(cacerts)) {
				trustStore.store(out, PASSWORD);
			}
			System.out.println("Removed compromised eMudhra roots from " + cacerts.getAbsolutePath());
		}
	}

	private static File cacerts(File jvmHome) {
		return new File(jvmHome, "lib/security/cacerts");
	}

	private static boolean removeFrom(KeyStore trustStore) throws Exception {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		boolean removed = false;
		for (String alias : Collections.list(trustStore.aliases())) {
			Certificate cert = trustStore.getCertificate(alias);
			if (cert != null && FINGERPRINTS.contains(HexFormat.of().formatHex(sha256.digest(cert.getEncoded())))) {
				trustStore.deleteEntry(alias);
				removed = true;
			}
		}
		return removed;
	}
}
