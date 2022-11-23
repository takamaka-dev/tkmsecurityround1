/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/UnitTests/JUnit5TestClass.java to edit this template
 */
package io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r2;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author tyranneo
 */
public class QTR2KeyPairGeneratorIT {
    
    public QTR2KeyPairGeneratorIT() {
    }
    
    @BeforeAll
    public static void setUpClass() {
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
     * Test of internalJavaKeypairFromBCPostQuantumKeyPair method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testInternalJavaKeypairFromBCPostQuantumKeyPair() throws Exception {
        System.out.println("internalJavaKeypairFromBCPostQuantumKeyPair");
        AsymmetricCipherKeyPair ackp = null;
        KeyPair expResult = null;
        KeyPair result = QTR2KeyPairGenerator.internalJavaKeypairFromBCPostQuantumKeyPair(ackp);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of internalSigner method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testInternalSigner() throws Exception {
        System.out.println("internalSigner");
        PrivateKey priv = null;
        byte[] data = null;
        byte[] expResult = null;
        byte[] result = QTR2KeyPairGenerator.internalSigner(priv, data);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of internalVerifier method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testInternalVerifier() throws Exception {
        System.out.println("internalVerifier");
        PublicKey pub = null;
        byte[] signature = null;
        byte[] data = null;
        boolean expResult = false;
        boolean result = QTR2KeyPairGenerator.internalVerifier(pub, signature, data);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getSignatureInstance method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetSignatureInstance() throws Exception {
        System.out.println("getSignatureInstance");
        Signature expResult = null;
        Signature result = QTR2KeyPairGenerator.getSignatureInstance();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of internalPublicKeyFromEncoded method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testInternalPublicKeyFromEncoded() throws Exception {
        System.out.println("internalPublicKeyFromEncoded");
        byte[] encoded = null;
        PublicKey expResult = null;
        PublicKey result = QTR2KeyPairGenerator.internalPublicKeyFromEncoded(encoded);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of publicKeyFromEncoded method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testPublicKeyFromEncoded() throws Exception {
        System.out.println("publicKeyFromEncoded");
        byte[] encoded = null;
        QTR2KeyPairGenerator instance = new QTR2KeyPairGenerator();
        PublicKey expResult = null;
        PublicKey result = instance.publicKeyFromEncoded(encoded);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getGenerator method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetGenerator() {
        System.out.println("getGenerator");
        QTESLAKeyPairGenerator expResult = null;
        QTESLAKeyPairGenerator result = QTR2KeyPairGenerator.getGenerator();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getGenerationParameters method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetGenerationParameters() {
        System.out.println("getGenerationParameters");
        SecureRandom sr = null;
        QTESLAKeyGenerationParameters expResult = null;
        QTESLAKeyGenerationParameters result = QTR2KeyPairGenerator.getGenerationParameters(sr);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getKeyPair method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetKeyPair() {
        System.out.println("getKeyPair");
        SecureRandom sr = null;
        AsymmetricCipherKeyPair expResult = null;
        AsymmetricCipherKeyPair result = QTR2KeyPairGenerator.getKeyPair(sr);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getStringPublicKey method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetStringPublicKey() throws Exception {
        System.out.println("getStringPublicKey");
        AsymmetricCipherKeyPair ackp = null;
        String expResult = "";
        String result = QTR2KeyPairGenerator.getStringPublicKey(ackp);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getBytePublicKey method, of class QTR2KeyPairGenerator.
     */
    @Test
    public void testGetBytePublicKey() throws Exception {
        System.out.println("getBytePublicKey");
        AsymmetricCipherKeyPair ackp = null;
        byte[] expResult = null;
        byte[] result = QTR2KeyPairGenerator.getBytePublicKey(ackp);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
}
