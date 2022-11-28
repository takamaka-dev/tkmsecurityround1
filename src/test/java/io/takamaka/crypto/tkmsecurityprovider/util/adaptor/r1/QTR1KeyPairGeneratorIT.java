/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/UnitTests/JUnit5TestClass.java to edit this template
 */
package io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r1;

import io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1.QTESLAPrivateKeyParameters;
import io.takamaka.crypto.tkmsecurityprovider.util.SeededRandomTestOnly;
import io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r1.QTR1KeyPairGenerator;
import io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r2.QTR2KeyPairGenerator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.util.encoders.UrlBase64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.platform.commons.function.Try.success;

/**
 * @author tyranneo
 */
public class QTR1KeyPairGeneratorIT {
    
    
    static AsymmetricCipherKeyPair pkPair;
    
    static QTESLAPrivateKeyParameters q;
    
    static SeededRandomTestOnly  seededRandomTestOnly;

    static final String qtk1provableSecure_r1 = "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";
    
    static char[] seed = {'a','b','c'};
    
    static byte[] scope = {'_','/','y'};
    
    public QTR1KeyPairGeneratorIT() {
    }
    
    @BeforeAll
    public static void setUpClass() throws IOException {

        seededRandomTestOnly = new SeededRandomTestOnly(seed, scope, 1);
        pkPair = QTR1KeyPairGenerator.getKeyPair(seededRandomTestOnly);
        AsymmetricKeyParameter aPrivate = pkPair.getPrivate();
        q = (QTESLAPrivateKeyParameters) aPrivate;
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of getKeyPair method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetKeyPair() {
        System.out.println("getKeyPair");
        
        SeededRandomTestOnly srto = new SeededRandomTestOnly(seed, scope, 1);
        AsymmetricCipherKeyPair pkPairTest = QTR1KeyPairGenerator.getKeyPair(srto);
        AsymmetricKeyParameter aPrivate = pkPairTest.getPrivate();
        QTESLAPrivateKeyParameters qQTESLAPrivateKeyParameters = (QTESLAPrivateKeyParameters) aPrivate;
        byte[] secret = qQTESLAPrivateKeyParameters.getSecret();
        int securityCategory = qQTESLAPrivateKeyParameters.getSecurityCategory();
        QTESLAPrivateKeyParameters qteslaPrivateKeyParameters = new QTESLAPrivateKeyParameters(securityCategory, secret);
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] encode = encoder.encode(secret);
        String privateKeyString = new String(encode, StandardCharsets.UTF_8);
        System.out.println(privateKeyString);
        assertArrayEquals(QTR1KeyPairGeneratorIT.q.getSecret(), qteslaPrivateKeyParameters.getSecret());
        assertEquals(QTR1KeyPairGeneratorIT.q.getSecurityCategory(), qteslaPrivateKeyParameters.getSecurityCategory());
        
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decode = decoder.decode(qtk1provableSecure_r1.getBytes(StandardCharsets.UTF_8));
        byte[] decodedSecret = decoder.decode(privateKeyString.getBytes(StandardCharsets.UTF_8));
        
        assertArrayEquals(decode, decodedSecret);
        
        success("The test case is successfull");
    }
    
}
