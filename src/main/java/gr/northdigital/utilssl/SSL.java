package gr.northdigital.utilssl;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.openssl.PEMReader;

import javax.crypto.Cipher;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Enumeration;

public class SSL {
  /**
   * Creates a certificate described by pem String parameter. The pem parameter must be in PEM format.
   *
   * @param pem
   * @return
   * @throws IOException
   */
  public static X509Certificate loadCertificateFromPemString(String pem) throws IOException {
    StringReader reader = new StringReader(pem);
    PEMReader pemReader = new PEMReader(reader);
    X509Certificate x509Certificate = (X509Certificate) pemReader.readObject();
    pemReader.close();

    return x509Certificate;
  }

  /**
   * Loads a certificate from the file system.
   *
   * @param filePath
   * @return
   * @throws Exception
   */
  public static X509Certificate loadCertificateFromFile(String filePath) throws Exception {
    if (!(new File(filePath)).exists()) {
      throw new Exception(String.format("File %s doesn't exist!", filePath));
    }

    InputStream inputStream = new FileInputStream(filePath);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
    inputStream.close();

    return x509Certificate;
  }

  /**
   * Loads a keystore from the file system.
   *
   * @param filePath
   * @param password
   * @return
   * @throws Exception
   */
  public static KeyStore loadKeyStoreFromFile(String filePath, String password) throws Exception {
    if (!(new File(filePath)).exists()) {
      throw new Exception(String.format("File %s doesn't exist!", filePath));
    }

    KeyStore keystore = KeyStore.getInstance("JKS");
    FileInputStream fileInputStream = new FileInputStream(filePath);
    keystore.load(fileInputStream, password.toCharArray());
    fileInputStream.close();

    return keystore;
  }

  /**
   * Return true if the certificate is self signed.
   *
   * @param x509Certificate
   * @return
   */
  public static boolean isSelfSignedCertificate(X509Certificate x509Certificate) {
    String subjectDN = x509Certificate.getSubjectDN().getName();
    String issuerDN = x509Certificate.getIssuerDN().getName();

    return subjectDN.equals(issuerDN);
  }

  /**
   * Returns true if the certificate is self signed and valid.
   *
   * @param x509Certificate
   * @return
   */
  public static boolean isSelfSignedCertificateValid(X509Certificate x509Certificate) {
    try {
      if (!isSelfSignedCertificate(x509Certificate))
        throw new Exception("The certificate is not self signed!");

      x509Certificate.verify(x509Certificate.getPublicKey());
      return true;
    } catch (Exception exc) {
      return false;
    }
  }

  /**
   * Returns true if the certificate can be validated against the supplied keyStore.
   * At the end of the certificate chain a self signed certificate is expended to be found.
   *
   * @param x509Certificate
   * @param keyStore
   * @return
   * @throws KeyStoreException
   */
  public static boolean isValidCertificate(X509Certificate x509Certificate, KeyStore keyStore) throws KeyStoreException {
    if (isSelfSignedCertificate(x509Certificate))
      return false;

    try {
      x509Certificate.checkValidity();
    } catch (CertificateExpiredException e) {
      return false;
    } catch (CertificateNotYetValidException e) {
      return false;
    }

    String issuerDN = x509Certificate.getIssuerDN().getName();
    Enumeration aliases = keyStore.aliases();

    while (aliases.hasMoreElements()) {
      String nextElement = (String) aliases.nextElement();
      X509Certificate nextCertificate = (X509Certificate) keyStore.getCertificate(nextElement);

      String nextCertificateSubjectDN = nextCertificate.getSubjectDN().getName();

      if (nextCertificateSubjectDN.equals(issuerDN)) {
        try {
          if (isSelfSignedCertificate(nextCertificate)) {
            if (!isSelfSignedCertificateValid(nextCertificate))
              return false;
          } else if (!isValidCertificate(nextCertificate, keyStore)) {
            return false;
          }

          x509Certificate.verify(nextCertificate.getPublicKey());

          return true;
        } catch (Exception ex) {
          return false;
        }
      }
    }

    return false;
  }

  /**
   * Returns true if the certificate can be validated against the supplied keyStore.
   * At the end of the certificate chain a self signed certificate is expended to be found.
   *
   * @param certificatePath
   * @param keyStorePath
   * @param keyStorePassword
   * @return
   * @throws Exception
   */
  public static boolean isValidCertificate(String certificatePath, String keyStorePath, String keyStorePassword) throws Exception {
    return isValidCertificate(loadCertificateFromFile(certificatePath), loadKeyStoreFromFile(keyStorePath, keyStorePassword));
  }

  /**
   * Returns the value of the requested certificate extension.
   *
   * @param x509Certificate
   * @param oid
   * @return
   * @throws IOException
   */
  public static String getExtensionValue(X509Certificate x509Certificate, String oid) throws IOException {
    byte[] extensionValue = x509Certificate.getExtensionValue(oid);

    ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(extensionValue));
    ASN1OctetString asn1OctetString = (ASN1OctetString) asn1InputStream.readObject();
    asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(asn1OctetString.getOctets()));
    String value = asn1InputStream.readObject().toString();
    return value;
  }

  public static String encryptTextWithKey(Key key, String text) {
    byte[] cipherText = null;

    try {
      final Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      cipherText = cipher.doFinal(text.getBytes());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return Hex.encodeHexString(cipherText);
  }

  public static String decryptTextWithKey(Key key, String text) {
    byte[] dectyptedText = null;
    try {
      final Cipher cipher = Cipher.getInstance("RSA");

      cipher.init(Cipher.DECRYPT_MODE, key);
      dectyptedText = cipher.doFinal(Hex.decodeHex(text.toCharArray()));

    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return new String(dectyptedText);
  }
}
