package com.example.testcrl;

import android.os.AsyncTask;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class OpenUrlInBackground extends AsyncTask<String, Void, UrlTestResult> {

//    @Override
//    protected UrlTestResult doInBackground(String... urls) {
//        UrlTestResult result = new UrlTestResult();
//        OkHttpClient client = null;
//        String url = urls[0];
//        if (!url.startsWith("https")) {
//            url = "https://" + url;
//        }
//
//        try {
//            client = new OkHttpClient.Builder()
//                    .sslSocketFactory(buildSocketFactory(), buildTrustManager())
//                    .retryOnConnectionFailure(true).build();
//        } catch (NoSuchAlgorithmException e) {
//            result.LastException = e;
//            return result;
//        } catch (KeyStoreException e) {
//            result.LastException = e;
//            return result;
//        } catch (SSLInitializationException e) {
//            result.LastException = e;
//            return result;
//        }
//
//        Request request = new Request.Builder()
//                .url(url)
//                .build();
//        try (Response response = client.newCall(request).execute()) {
//            Log.d("", response.body().string());
//            result.IsSuccess = true;
//            return result;
//        } catch (SSLHandshakeException e) {
//            result.LastException = e;
//            return result;
//        } catch (IOException e) {
//            result.LastException = e;
//            return result;
//        }
//    }

    private SSLSocketFactory buildSocketFactory() throws SSLInitializationException {
        final SSLContext sslContext;
        final SecureRandom secureRandom = new SecureRandom();
        try {
            KeyStore customKeyStore = KeyStore.getInstance("AndroidCAStore");
            customKeyStore.load(null, null);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(customKeyStore, null);
            sslContext = SSLContext.getInstance("TLS");
            TrustManager tm = buildTrustManager();
            sslContext.init(
                    kmf.getKeyManagers(),
                    new TrustManager[]{
                            tm
                    },
                    secureRandom
            );
            return sslContext.getSocketFactory();
        } catch (final NoSuchAlgorithmException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (final KeyManagementException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (KeyStoreException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (FileNotFoundException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (UnrecoverableKeyException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (CertificateException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (IOException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        }
    }

    private X509TrustManager buildTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        final TrustManagerFactory javaDefaultTrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        javaDefaultTrustManager.init((KeyStore) null);
        final TrustManagerFactory customCaTrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        customCaTrustManager.init((KeyStore) null);
        return new TrustManagerDelegate(
                (X509TrustManager) customCaTrustManager.getTrustManagers()[0],
                (X509TrustManager) javaDefaultTrustManager.getTrustManagers()[0]
        );
    }

    @Override
    protected UrlTestResult doInBackground(String... strings) {
        URL url = null;
        try {
            url = new URL(strings[0]);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        try {
            HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
            urlConnection.connect();
            Certificate[] certs = urlConnection.getServerCertificates();
            if(certs.length > 0)
            {

            }
        } catch (IOException e) {
            e.printStackTrace();
        }

       return new UrlTestResult();
    }

    private List<String> getCrlUrls(X509Certificate certificate)
    {
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
        }catch (Exception e)
        {

        }
        return crlUrls;
    }

}
