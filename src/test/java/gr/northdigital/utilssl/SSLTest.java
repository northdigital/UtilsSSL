package gr.northdigital.utilssl;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SSLTest {
  private final static String BASE_PATH = "C:\\Users\\Panagiotis\\Desktop\\ssl\\";

  //@Test
  public void isValidCertificate() throws Exception {
    KeyStore keyStore = SSL.loadKeyStoreFromFile(BASE_PATH + "keys.jks", "sporades");
    X509Certificate x509Certificate = SSL.loadCertificateFromFile(BASE_PATH + "user2.cer");
    boolean isValid = SSL.isValidCertificate(x509Certificate, keyStore);

    Assert.assertTrue(isValid);
  }

  //@Test
  public void encryptWithAssymetricKey() throws Exception {
    KeyStore keyStore = SSL.loadKeyStoreFromFile(BASE_PATH + "keys.jks", "sporades");
    X509Certificate cer = ((X509Certificate) keyStore.getCertificate("root"));
    PublicKey pubKey = cer.getPublicKey();
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("root", "sporades".toCharArray());

    String unencrypted = "user1 password1 key1";
    //String encrypted = SSL.encryptTextWithKey(pubKey, unencrypted);
    String encrypted = "15e45109a7716032b11a87001df26e5d9cdb77c33344764ba2b04e6e408575c061b7331ed65656a3316e225294b58c6da8d85fd6ba060f4b8126de25da83fafb50831262b84290b24abb77ef102e447155ae26842f4178eabd8547c72637b9cff3a88325dca6694282f00f8da50885049cacdc05f1672273cf3e442dfd44093b2e59534aae2bf1ae202b3f8a05f2df0afd491e429b8b89d594a29d1336f14203a52f6da5c33867bcb40a5f7cb184391242f1cae826feb7eaf5600306bb972e633a9b2efa7c4af5b4cc3c931f0053ada0a57e4cf71be61e93264b446a03eeafd43c7e495cac53e53d935732f236ae668dec9c40c3797735e63e3d38994c12b8b862b8fd4855278a5f4a5042b979b5c971a5d37fb5ba05ccc3fffaaf5d20352a481367a983fee575b891d034b701e2b60f902341a0a8e228f594d8c5652ada9610f774bc5c7f80f0deb680905e47067dabe6843a2ca0f332ff0d7fbf6c86257c556ac442630be5e3b0226d959fea067e61c9bbc594560a867a89ec8e3378083bbe5b1fead88a734b4e4a9d95028f70244a948fffa9b33a6b2d712e90f9beff7bdb73092abc1f926cdfb3af1df54174ba1883f8599d9005b44f95380c8ccaecf200750694bcf76fc8f0eeae1b08132ac6c5cb4fabc27a86cf0d2b22f97555ab3963f511ea983ba950542cee38b6d0fddc1137404d74a4819a15a02139e8eac962f8";
    String decrypted = SSL.decryptTextWithKey(privateKey, encrypted);

    Assert.assertTrue(unencrypted.equals(decrypted));
  }

  @Test
  public void generateSymmetricKey() throws Exception {
//    KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
//    aesKeyGen.init(256);
//
//    SecretKey secretKey = aesKeyGen.generateKey();
//    byte[] raw = secretKey.getEncoded();
//    String hexString = Hex.encodeHexString(raw);

    KeyStore keyStore = SSL.createKeyStore(BASE_PATH + "test.jks", "sporades");
    SSL.addKeyPair(keyStore, "user1", "sporades", 100);
    SSL.saveKeyStore(keyStore,BASE_PATH + "test.jks", "sporades");

    //KeyStore keyStore = SSL.loadKeyStoreFromFile(BASE_PATH + "test.jks", "sporades");
    //Key key = keyStore.getKey("root.PK", "sporades".toCharArray());

    Assert.assertTrue(true);
  }
}