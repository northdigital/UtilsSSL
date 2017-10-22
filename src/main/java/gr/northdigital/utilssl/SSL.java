package gr.northdigital.utilssl;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Enumeration;

public class SSL {
  /**
   * Creates a certificate described by pem String parameter. The pem parameter must be in PEM format.
   *
   * @param pem
   * @return
   * @throws IOException
   */
  public static X509Certificate loadCertificateFromPemString(String pem) throws IOException, CertificateException {
    StringReader reader = new StringReader(pem);
    PEMParser pemReader = new PEMParser(reader);
    X509CertificateHolder x509CertificateHolder = ((X509CertificateHolder)(pemReader.readObject()));
    X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate(x509CertificateHolder);
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

  public static void saveKeyStore(KeyStore keyStore, String path, String password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    FileOutputStream fileOutputStream = new FileOutputStream(path);
    keyStore.store(fileOutputStream, password.toCharArray());
    fileOutputStream.close();
  }

  private static final int KEY_SIZE = 1024;

  public static KeyPair addKeyPair(KeyStore keyStore, String name, String password) throws Exception {
    X509Certificate[] chain = new X509Certificate[1];

    KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
    SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rsaKeyGen.initialize(KEY_SIZE, secureRandom);
    KeyPair keyPair = rsaKeyGen.genKeyPair();

    X509Certificate x509Certificate = CACertBuilder.createCACert(keyPair.getPublic(), keyPair.getPrivate(), name);
    chain[0] = x509Certificate;

    keyStore.setKeyEntry(name + ".pk", keyPair.getPrivate(), password.toCharArray(), chain);

    return keyPair;
  }

  public static KeyStore createKeyStore(String path, String password) throws Exception {
    KeyStore keyStore;
    keyStore = KeyStore.getInstance("JKS");
    keyStore.load(null);

    addKeyPair(keyStore, "root", password);

    return keyStore;
  }

  public static X509Certificate createUserCertificate(KeyStore keyStore, String keyStorePassword, String name, String userName,
                                                      String password) throws Exception {
    KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
    SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rsaKeyGen.initialize(KEY_SIZE, secureRandom);
    KeyPair keyPair = rsaKeyGen.genKeyPair();
    PublicKey publicKey = keyPair.getPublic();

    X509Certificate caCertificate = (X509Certificate) keyStore.getCertificate("root.pk");
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("root.pk", keyStorePassword.toCharArray());

    X509Certificate x509Certificate =
      IntermediateCertBuilder.createIntermediateCert(publicKey, privateKey, caCertificate, name, userName, password);

    return x509Certificate;
  }

  public static void saveCertificate(X509Certificate x509Certificate, String certFilePath) throws IOException {
    FileWriter fw = new FileWriter(certFilePath);
    StringWriter sw = new StringWriter();
    try {
      sw.write("-----BEGIN CERTIFICATE-----\n");
      sw.write(DatatypeConverter.printBase64Binary(x509Certificate.getEncoded()).replaceAll("(.{64})", "$1\n"));
      sw.write("\n-----END CERTIFICATE-----\n");
    } catch (CertificateEncodingException e) {
      e.printStackTrace();
    }
    fw.write(sw.toString());
    fw.close();
  }

  public static String generateSymmetricKey() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] generateSeed = secureRandom.generateSeed(32);
    String hexSeed = Hex.encodeHexString(generateSeed);

    return hexSeed;
  }
}
