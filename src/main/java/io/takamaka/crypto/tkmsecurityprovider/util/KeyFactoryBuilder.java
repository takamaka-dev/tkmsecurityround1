/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.util;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/**
 *
 * @author giovanni.antino@h2tcoin.com
 */
public class KeyFactoryBuilder {
/*
    public static void main(String[] args) {
        KeyFactory kf;
        kf = new KeyFactory(new KeyFactorySpi() {
            @Override
            protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
                if (keySpec instanceof PKCS8EncodedKeySpec) {
                    // get the DER-encoded Key according to PKCS#8 from the spec
                    byte[] encKey = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

                    try {
                        return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
                    } catch (Exception e) {
                        throw new InvalidKeySpecException(e.toString());
                    }
                }

                throw new InvalidKeySpecException("Unsupported key specification: "
                        + keySpec.getClass() + ".");
            }

            @Override
            protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
                throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            }

            @Override
            protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
                throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            }

            @Override
            protected Key engineTranslateKey(Key key) throws InvalidKeyException {
                throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            }
        }, new Provider("TKMINTERNAL", "0.1", "custom provider") {
        }, "QTESLA_P_I_ROUND_I") {
        };
    }*/
}
