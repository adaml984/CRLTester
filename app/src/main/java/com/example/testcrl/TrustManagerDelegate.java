package com.example.testcrl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
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
//        try {
//            this.mainTrustManager.checkServerTrusted(chain, authType);
//        } catch (CertificateException ex) {
//            this.trustManager.checkServerTrusted(chain, authType);
//        }
        try {
            X509Certificate[] reorderedChain = reorderCertificateChain(chain);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            CertPath certPath = factory.generateCertPath(Arrays.asList(reorderedChain));
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            PKIXParameters params = new PKIXParameters(ks);
            params.setRevocationEnabled(true);
            validator.validate(certPath, params);
        }  catch (NoSuchAlgorithmException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (KeyStoreException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (IOException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        } catch (CertPathValidatorException e) {
            throw new SSLInitializationException(e.getLocalizedMessage(), e);
        }
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
