package com.example.testcrl;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.X509TrustManager;

public class TrustManagerDelegate implements X509TrustManager{
    private final X509TrustManager mainTrustManager;
    private final X509TrustManager trustManager;

    public TrustManagerDelegate(X509TrustManager mainTrustManager, X509TrustManager trustManager) {
        this.mainTrustManager = mainTrustManager;
        this.trustManager = trustManager;
    }

    @Override
    public void checkClientTrusted(
            final X509Certificate[] chain, final String authType) throws CertificateException {
        try {
            this.trustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException ex) {
            this.mainTrustManager.checkServerTrusted(chain, authType);
        }
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        try {
            X509Certificate[] reorderedChain = reorderCertificateChain(chain);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            CertPath certPath = factory.generateCertPath(Arrays.asList(reorderedChain));
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            PKIXParameters params = new PKIXParameters(ks);
            params.setRevocationEnabled(false);
            validator.validate(certPath, params);
            for(X509Certificate cert : reorderedChain){
                validateCrl(cert);
            }
        }  catch (NoSuchAlgorithmException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (KeyStoreException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (IOException e) {
            throw new SSLInitializationException(e.getMessage(), e);
        } catch (CertPathValidatorException e) {
            throw new SSLInitializationException(e.getMessage(), e);
        }
    }

    private void validateCrl(Certificate certificate) throws SSLInitializationException {
        List<String> crlUrls = getCrlUrls((X509Certificate) certificate);
        for (String crlUrl : crlUrls) {
            X509CRL crlObject = getCrlObject(crlUrl);
            if (crlObject != null) {
                X509CRLEntry entry = crlObject.getRevokedCertificate((X509Certificate) certificate);
                if (entry != null) {
                    throw new SSLInitializationException("Certificate found on CRL",null);
                }
            }
        }
    }

    private List<String> getCrlUrls(X509Certificate certificate) {
        List<String> crlUrls = new ArrayList<String>();
        try {
            byte[] crldpExt = certificate.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crldpExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(
                    new ByteArrayInputStream(crldpExtOctets));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        for (GeneralName genName : genNames) {
                            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String url = DERIA5String.getInstance(
                                        genName.getName()).getString();
                                crlUrls.add(url);

                            }
                        }
                    }
                }
            }
        } catch (Exception e) {

        }
        return crlUrls;
    }

    private X509CRL getCrlObject(String crlURL) {
        URL url = null;
        try {
            url = new URL(crlURL);
            InputStream crlStream = url.openStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
            crlStream.close();
            return crl;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private X509Certificate findSigner(X509Certificate signedCert, List<X509Certificate> certificates) {
        X509Certificate signer = null;

        for(X509Certificate cert : certificates) {
            Principal certSubjectDN = cert.getSubjectDN();
            Principal issuerDN = signedCert.getIssuerDN();
            if(certSubjectDN.equals(issuerDN)) {
                signer = cert;
                break;
            }
        }

        return signer;
    }

    private X509Certificate findRootCert(List<X509Certificate> certificates) {
        X509Certificate rootCert = null;

        for(X509Certificate cert : certificates) {
            X509Certificate signer = findSigner(cert, certificates);
            if(signer == null || signer.equals(cert)) { // no signer present, or self-signed
                rootCert = cert;
                break;
            }
        }

        return rootCert;
    }

    private X509Certificate findSignedCert(X509Certificate signingCert, List<X509Certificate> certificates) {
        X509Certificate signed = null;

        for(X509Certificate cert : certificates) {
            Principal signingCertSubjectDN = signingCert.getSubjectDN();
            Principal certIssuerDN = cert.getIssuerDN();
            if(certIssuerDN.equals(signingCertSubjectDN) && !cert.equals(signingCert)) {
                signed = cert;
                break;
            }
        }

        return signed;
    }

    private X509Certificate[] reorderCertificateChain(X509Certificate[] chain) {

        X509Certificate[] reorderedChain = new X509Certificate[chain.length];
        List<X509Certificate> certificates = Arrays.asList(chain);

        int position = chain.length - 1;
        X509Certificate rootCert = findRootCert(certificates);
        reorderedChain[position] = rootCert;

        X509Certificate cert = rootCert;
        while((cert = findSignedCert(cert, certificates)) != null && position > 0) {
            reorderedChain[--position] = cert;
        }

        return reorderedChain;
    }


    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return this.trustManager.getAcceptedIssuers();
    }

}
