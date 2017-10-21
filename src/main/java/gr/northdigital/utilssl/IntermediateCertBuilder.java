package gr.northdigital.utilssl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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

  public static X509Certificate createIntermediateCert(PublicKey pubKey, PrivateKey caPrivateKey, X509Certificate caCertificate, String name) throws Exception {
    X500NameBuilder nameBuilder = new X500NameBuilder();

    nameBuilder.addRDN(BCStyle.C, name);
    //nameBuilder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
    //nameBuilder.addRDN(BCStyle.OU, "Bouncy Intermediate Certificate");
    //nameBuilder.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

    X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(caCertificate, BigInteger.valueOf(2),
      new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
      nameBuilder.build(), pubKey);

    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

    v3Bldr.addExtension(Extension.subjectKeyIdentifier,false, extUtils.createSubjectKeyIdentifier(pubKey));
    v3Bldr.addExtension(Extension.authorityKeyIdentifier,false, extUtils.createAuthorityKeyIdentifier(caCertificate));
    v3Bldr.addExtension(Extension.basicConstraints,false, new BasicConstraints(0));

    v3Bldr.addExtension((new ASN1ObjectIdentifier("2.16.840.1.113730.1.13")).intern(),false, "1 2 3".getBytes());

    X509CertificateHolder certHldr = v3Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(caPrivateKey));
    X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);
    x509Certificate.checkValidity(new Date());
    x509Certificate.verify(caCertificate.getPublicKey());
    PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) x509Certificate;
    //bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Intermediate Certificate"));

    return x509Certificate;
  }
}
