/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;
import org.bouncycastle.util.encoders.UrlBase64;

/**
 *
 * @author giovanni.antino@h2tcoin.com
 */
public class QTR2KeyPairGenerator {

    public static Signature signature;
    public static final Object SIGLOCK = new Object();
    //public static BouncyCastlePQCProvider bouncyCastlePQCProvider;

    public static KeyPair internalJavaKeypairFromBCPostQuantumKeyPair(AsymmetricCipherKeyPair ackp) throws IOException {
        synchronized (SIGLOCK) {
            PrivateKeyInfo privateKeyInfo = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(ackp.getPrivate());
            SubjectPublicKeyInfo publicKeyInfo = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ackp.getPublic());
            PrivateKey privateKey = BouncyCastlePQCProvider.getPrivateKey(privateKeyInfo);
            PublicKey publicKey = BouncyCastlePQCProvider.getPublicKey(publicKeyInfo);
            return new KeyPair(publicKey, privateKey);
        }
    }

    public static byte[] internalSigner(PrivateKey priv, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        synchronized (SIGLOCK) {
            //BouncyCastlePQCProvider bouncyCastlePQCProvider = new BouncyCastlePQCProvider();
            //Provider.Service service = bouncyCastlePQCProvider.getService("Signature", "QTESLA-P-I");
            //Signature sigInstance = Signature.getInstance("QTESLA-P-I", bouncyCastlePQCProvider);
            Signature sigInstance = getSignatureInstance();
            sigInstance.initSign(priv);
            sigInstance.update(data);
            return sigInstance.sign();
        }
    }

    public static boolean internalVerifier(PublicKey pub, byte[] signature, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        synchronized (SIGLOCK) {
            //BouncyCastlePQCProvider bouncyCastlePQCProvider = new BouncyCastlePQCProvider();
            //Provider.Service service = bouncyCastlePQCProvider.getService("Signature", "QTESLA-P-I");
            //Signature sigInstance = Signature.getInstance("QTESLA-P-I", bouncyCastlePQCProvider);
            Signature sigInstance = getSignatureInstance();
            sigInstance.initVerify(pub);
            sigInstance.update(data);
            return sigInstance.verify(signature);
        }
    }

    public static Signature getSignatureInstance() throws NoSuchAlgorithmException {
        BouncyCastlePQCProvider bouncyCastlePQCProvider = new BouncyCastlePQCProvider();
        //Provider.Service service = bouncyCastlePQCProvider.getService("Signature", "QTESLA-P-I");
        return Signature.getInstance("QTESLA-P-I", bouncyCastlePQCProvider);
    }

    public static PublicKey internalPublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        synchronized (SIGLOCK) {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
            QTESLAKeyFactorySpi qfs = new QTESLAKeyFactorySpi();
            return qfs.engineGeneratePublic(pubKeySpec);
        }
    }

    /**
     * BC_QTESLA_PS_SC_1_ROUND_2
     */
    /*
    public KeyPairGeneratorBC_QTESLA_PS_SC_1_ROUND_2() throws NoSuchAlgorithmException {
        bouncyCastlePQCProvider = new BouncyCastlePQCProvider();
        //bouncyCastlePQCProvider.Security.addProvider(new BouncyCastlePQCProvider());
        //KeyPairGeneratorBC_QTESLA_PS_SC_1_ROUND_2.bouncyCastlePQCProvider.getS
        signature = Signature.getInstance("QTESLA-P-I");
    }

    public static Signature getSignature() {
        return signature;
    }

    private static final KeyPair getJKPfromBDACKP_PQ(AsymmetricCipherKeyPair ackp) {
        try {
            PrivateKeyInfo privateKeyInfo = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(ackp.getPrivate());
            SubjectPublicKeyInfo publicKeyInfo = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ackp.getPublic());
            PrivateKey privateKey = BouncyCastlePQCProvider.getPrivateKey(privateKeyInfo);
            PublicKey publicKey = BouncyCastlePQCProvider.getPublicKey(publicKeyInfo);
            return new KeyPair(publicKey, privateKey);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
     */
    public PublicKey publicKeyFromEncoded(byte[] encoded) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory;
        switch (encoded.length) {
            case 14904:
                QTESLAKeyFactorySpi qfs = new QTESLAKeyFactorySpi();
                return qfs.engineGeneratePublic(pubKeySpec);
            default:
                throw new UnsupportedOperationException("key not recognized");

        }
        //return keyFactory.generatePublic(pubKeySpec);

    }

    /**
     * BC_QTESLA_PS_SC_1_ROUND_2
     *
     * @return
     */
    public static QTESLAKeyPairGenerator getGenerator() {
        return new QTESLAKeyPairGenerator();
    }

    /**
     * BC_QTESLA_PS_SC_1_ROUND_2
     *
     * @param sr
     * @return
     */
    public static QTESLAKeyGenerationParameters getGenerationParameters(SecureRandom sr) {
        return new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_I, sr);
    }

    /**
     * BC_QTESLA_PS_SC_1_ROUND_2
     *
     * @param sr
     * @return
     */
    public static AsymmetricCipherKeyPair getKeyPair(SecureRandom sr) {
        QTESLAKeyGenerationParameters generationParameters = getGenerationParameters(sr);
        QTESLAKeyPairGenerator generator = getGenerator();
        generator.init(generationParameters);
        return generator.generateKeyPair();
    }

    public static String getStringPublicKey(AsymmetricCipherKeyPair ackp) throws IOException {
        UrlBase64 b64e = new UrlBase64();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AsymmetricKeyParameter aPublic = ackp.getPublic();
        QTESLAPublicKeyParameters qtPubKey = (QTESLAPublicKeyParameters) aPublic;
        UrlBase64.encode(qtPubKey.getPublicData(), baos);
        String stringPublicKey = baos.toString();
        baos.close();
        return stringPublicKey;
    }

    public static byte[] getBytePublicKey(AsymmetricCipherKeyPair ackp) throws IOException {
        UrlBase64 b64e = new UrlBase64();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AsymmetricKeyParameter aPublic = ackp.getPublic();
        QTESLAPublicKeyParameters qtPubKey = (QTESLAPublicKeyParameters) aPublic;
        UrlBase64.encode(qtPubKey.getPublicData(), baos);
        byte[] toByteArray = baos.toByteArray();
        baos.close();
        return toByteArray;
    }
}
