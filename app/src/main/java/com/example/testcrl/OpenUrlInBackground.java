package com.example.testcrl;

import android.os.AsyncTask;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class OpenUrlInBackground extends AsyncTask<String, Void, Boolean> {
    @Override
    protected Boolean doInBackground(String... urls) {
        OkHttpClient client = null;
        String url = urls[0];
        if(!url.startsWith("https")){
            url = "https://" + url;
        }

        try {
            client = new OkHttpClient.Builder()
                    .sslSocketFactory(buildSocketFactory(), buildTrustManager())
                    .retryOnConnectionFailure(true).build();
        } catch (SSLInitializationException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        Request request = new Request.Builder()
                .url(url)
                .build();

        try (Response response = client.newCall(request).execute()) {
            Log.d("", response.body().string()) ;
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

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
        javaDefaultTrustManager.init((KeyStore)null);
        final TrustManagerFactory customCaTrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        customCaTrustManager.init((KeyStore)null);
        return new TrustManagerDelegate(
                (X509TrustManager)customCaTrustManager.getTrustManagers()[0],
                (X509TrustManager)javaDefaultTrustManager.getTrustManagers()[0]
        );
    }
}
