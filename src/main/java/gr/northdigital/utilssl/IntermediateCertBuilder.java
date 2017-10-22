package gr.northdigital.utilssl;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class IntermediateCertBuilder {

  public static X509Certificate createIntermediateCert(PublicKey pubKey, PrivateKey caPrivateKey, X509Certificate caCertificate,
                                                       String name, String userName, String password) throws Exception {
    X500NameBuilder nameBuilder = new X500NameBuilder();

    nameBuilder.addRDN(BCStyle.C, name);

    long nowms = System.currentTimeMillis();
    Date validFromDate = new Date(nowms - (1000L * 60 * 60 * 24 * 365 * 1));
    Date validToDate = new Date(nowms + (1000L * 60 * 60 * 24 * 365 * 100));
    X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
      caCertificate, BigInteger.valueOf(2), validFromDate, validToDate, nameBuilder.build(), pubKey);

    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

    x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier,false, extUtils.createSubjectKeyIdentifier(pubKey));
    x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier,false, extUtils.createAuthorityKeyIdentifier(caCertificate));
    x509v3CertificateBuilder.addExtension(Extension.basicConstraints,false, new BasicConstraints(0));

    String symmetricKey = SSL.getExtensionValue(caCertificate, "2.16.840.1.113730.1.13");

    DERIA5String netscapeComment = new DERIA5String(
      SSL.encryptTextWithKey(caCertificate.getPublicKey(), userName) + " " +
        SSL.encryptTextWithKey(caCertificate.getPublicKey(), password ) + " " +
        symmetricKey);
    byte[] netscapeCommentEncoded = netscapeComment.getEncoded(ASN1Encoding.DER);

    Extension extension = new Extension(new ASN1ObjectIdentifier("2.16.840.1.113730.1.13"), false, netscapeCommentEncoded);
    x509v3CertificateBuilder.addExtension(extension);

    X509CertificateHolder certHldr = x509v3CertificateBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caPrivateKey));
    X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);
    x509Certificate.checkValidity(new Date());
    x509Certificate.verify(caCertificate.getPublicKey());
    PKCS12BagAttributeCarrier pkcs12BagAttributeCarrier = (PKCS12BagAttributeCarrier) x509Certificate;
    pkcs12BagAttributeCarrier.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("End User Certificate"));

    return x509Certificate;
  }
}
