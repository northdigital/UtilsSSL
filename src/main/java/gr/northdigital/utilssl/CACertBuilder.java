package gr.northdigital.utilssl;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.commons.io.IOUtils;

public class CACertBuilder {
  private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 86400000L * 365);
  private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + 86400000L * 365 * 100);
  private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
  private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

  private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws IOException {
    ASN1InputStream is = null;
    try {
      is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded()));
      ASN1Sequence seq = (ASN1Sequence) is.readObject();
      SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(seq); //new SubjectPublicKeyInfo(seq);
      return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
    } finally {
      IOUtils.closeQuietly(is);
    }
  }

  private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws OperatorCreationException, CertificateException {
    ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
    return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
  }

  /**
   * Create a certificate to use by a Certificate Authority, signed by a self signed certificate.
   */
  public static X509Certificate createCACert(PublicKey publicKey, PrivateKey privateKey, String name) throws Exception {

    X500Name issuerName = new X500Name("CN=" + name + ".ca");
    X500Name subjectName = issuerName;
    BigInteger serial = BigInteger.valueOf(new Random().nextInt());

    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, NOT_BEFORE, NOT_AFTER, subjectName, publicKey);
    builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey));
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
    builder.addExtension(Extension.keyUsage, false, usage);

    ASN1EncodableVector purposes = new ASN1EncodableVector();
    purposes.add(KeyPurposeId.id_kp_serverAuth);
    purposes.add(KeyPurposeId.id_kp_clientAuth);
    purposes.add(KeyPurposeId.anyExtendedKeyUsage);
    builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

    X509Certificate cert = signCertificate(builder, privateKey);
    cert.checkValidity(new Date());
    cert.verify(publicKey);

    return cert;
  }
}
