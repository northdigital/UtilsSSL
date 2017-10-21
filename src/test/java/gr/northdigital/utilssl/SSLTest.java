package gr.northdigital.utilssl;

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyStore;
import java.security.Security;

public class SSLTest {
  private final static String BASE_PATH = "C:\\Users\\Panagiotis\\Desktop\\ssl\\";

  @Test
  public void test1() throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyStore keyStore = SSL.createKeyStore(BASE_PATH + "test.jks", "sporades");
    SSL.addKeyPair(keyStore, "user1", "sporades");
    SSL.saveKeyStore(keyStore,BASE_PATH + "test.jks", "sporades");

    Assert.assertTrue(true);
  }
 }