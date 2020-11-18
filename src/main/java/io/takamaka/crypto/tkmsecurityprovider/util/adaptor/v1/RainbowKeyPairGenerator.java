/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.util.adaptor.v1;

import java.io.IOException;
import static java.lang.String.format;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Formatter;
import java.util.Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 *
 * @author giovanni.antino@h2tcoin.com
 */
public class RainbowKeyPairGenerator {

    public static Signature signature;
    public static final Object SIGLOCK = new Object();

    public static KeyPair internalJavaKeypairFromBCPostQuantumKeyPair(AsymmetricCipherKeyPair ackp) throws IOException {
        synchronized (SIGLOCK) {
            PrivateKeyInfo privateKeyInfo = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(ackp.getPrivate());
            SubjectPublicKeyInfo publicKeyInfo = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ackp.getPublic());
            PrivateKey privateKey = BouncyCastlePQCProvider.getPrivateKey(privateKeyInfo);
            PublicKey publicKey = BouncyCastlePQCProvider.getPublicKey(publicKeyInfo);
            return new KeyPair(publicKey, privateKey);
        }
    }

    public static Signature getSignatureInstance() throws NoSuchAlgorithmException {
        BouncyCastlePQCProvider bouncyCastlePQCProvider = new BouncyCastlePQCProvider();
        //Provider.Service service = bouncyCastlePQCProvider.getService("Signature", "QTESLA-P-I");
        return Signature.getInstance("Rainbow", bouncyCastlePQCProvider);
    }

    public static void main(String[] args) {
        BouncyCastlePQCProvider bouncyCastlePQCProvider = new BouncyCastlePQCProvider();
        Set<Provider.Service> services = bouncyCastlePQCProvider.getServices();
        System.out.println("S");
        services.forEach(s -> {
            System.out.printf("S: %s %s %s %s", s.getAlgorithm(), s.getProvider().getName(), s.getClassName(), s.toString());
            //System.out.println("S: " s.getAlgorithm());
        });

    }

    /*
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
     */
}
