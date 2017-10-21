package gr.northdigital.utilssl;

import org.junit.Assert;
import org.junit.Test;

import java.security.*;
import java.security.cert.X509Certificate;

public class SSLTest {
  private final static String BASE_PATH = "C:\\Users\\Panagiotis\\Desktop\\ssl\\";

  @Test
  public void test1() throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyStore keyStore = SSL.createKeyStore(BASE_PATH + "test.jks", "sporades");
    X509Certificate user1cer = SSL.createUserCertificate(keyStore, "user1");
    keyStore.setCertificateEntry("user1", user1cer);

    SSL.saveKeyStore(keyStore,BASE_PATH + "test.jks", "sporades");

    Assert.assertTrue(true);
  }
 }