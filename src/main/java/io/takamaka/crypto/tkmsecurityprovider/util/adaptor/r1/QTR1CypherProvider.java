/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r1;

import io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1.QTESLAPublicKeyParameters;
import io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1.QTESLASecurityCategory;
import io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1.QTESLASigner;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.UrlBase64;

/**
 *
 * @author giovanni.antino@h2tcoin.com
 */
public class QTR1CypherProvider {

    public static final BCQTESLAPSSC1CypherBean sign(AsymmetricCipherKeyPair keyPair, String message) {
        BCQTESLAPSSC1CypherBean tcb = new BCQTESLAPSSC1CypherBean();
        tcb.setValid(false);
        try {
            byte[] byteMessage = Strings.toByteArray(message);
            QTESLASigner signer = new QTESLASigner();
            //signer.//.reset();
            signer.init(true, keyPair.getPrivate());
            //signer.update(byteMessage, 0, byteMessage.length);
            byte[] generatedSignature = signer.generateSignature(byteMessage);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            UrlBase64.encode(generatedSignature, baos);
            tcb.setSignature(baos.toString());
            tcb.setValid(true);
            baos.close();
        } catch (IOException ex) {
            tcb.setEx(ex);
            tcb.setValid(false);
        }
        return tcb;
    }

    public static final BCQTESLAPSSC1CypherBean verify(AsymmetricCipherKeyPair keyPair, String signature, String message) {
        BCQTESLAPSSC1CypherBean tcb = new BCQTESLAPSSC1CypherBean();
        tcb.setValid(false);
        QTESLAPublicKeyParameters publicK = null;
        QTESLASigner verifier;
        byte[] signatureByteArray = new byte[]{};
        byte[] messageByteArray = new byte[]{};
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            UrlBase64.decode(signature, baos);
            signatureByteArray = baos.toByteArray();
            messageByteArray = Strings.toByteArray(message);
            verifier = new QTESLASigner();
            //Ed25519PublicKeyParameters edPublicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();
            publicK = (QTESLAPublicKeyParameters) keyPair.getPublic();
            verifier.init(false, publicK);//here
            boolean validSignature = verifier.verifySignature(messageByteArray, signatureByteArray);
            tcb.setValid(validSignature);
            baos.close();
        } catch (IOException ex) {
            ex.printStackTrace();
            if (publicK != null) {
                System.out.println(publicK.getPublicData().toString());
            }
            System.out.println(signature);
            System.out.println(Arrays.toString(signatureByteArray));
            System.out.println(Arrays.toString(messageByteArray));
            tcb.setEx(ex);
            tcb.setValid(false);

        }
        return tcb;
    }

    public static final BCQTESLAPSSC1CypherBean verify(String publicKey, String signature, String message) {
        try {
            AsymmetricCipherKeyPair pkPair;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            UrlBase64.decode(publicKey, baos);
            QTESLAPublicKeyParameters edPublicKey = new QTESLAPublicKeyParameters(QTESLASecurityCategory.PROVABLY_SECURE_I, baos.toByteArray());
            baos.close();
            pkPair = new AsymmetricCipherKeyPair(edPublicKey, null);
            return verify(pkPair, signature, message);
        } catch (Exception ex) {
            ex.printStackTrace();
            BCQTESLAPSSC1CypherBean tcb = new BCQTESLAPSSC1CypherBean();
            tcb.setEx(ex);
            tcb.setValid(false);
            return tcb;
        }
    }
}
