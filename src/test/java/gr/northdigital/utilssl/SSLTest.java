package gr.northdigital.utilssl;

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class SSLTest {
  private final static String BASE_PATH = "C:\\Users\\Panagiotis\\Desktop\\ssl\\";

  @Test
  public void isValidCertificate() throws Exception {
    KeyStore keyStore = SSL.loadKeyStoreFromFile(BASE_PATH + "keys.jks", "sporades");
    X509Certificate x509Certificate = SSL.loadCertificateFromFile(BASE_PATH + "user2.cer");
    boolean isValid = SSL.isValidCertificate(x509Certificate, keyStore);

    Assert.assertTrue(isValid);
  }

  @org.junit.Test
  public void encryptWithAssymetricKey() throws Exception {
    KeyStore keyStore = SSL.loadKeyStoreFromFile(BASE_PATH + "keys.jks", "sporades");
    X509Certificate cer = ((X509Certificate) keyStore.getCertificate("root"));
    PublicKey pubKey = cer.getPublicKey();
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("root", "sporades".toCharArray());

    String unencrypted = "user1 password1 key1";
    String encrypted = SSL.encryptTextWithKey(pubKey, unencrypted);
    String decrypted = SSL.decryptTextWithKey(privateKey, encrypted);

    Assert.assertTrue(unencrypted.equals(decrypted));
  }
}