/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package io.takamaka.crypto.tkmsecurityprovider.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author tyranneo
 */
public class SeededRandomTestOnly extends SecureRandom {

    private char[] seed;
    private byte[] scope;
    private int keyNumber;
    //private int keyLength;

    /**
     *
     * @param seed
     * @param scope
     * @param keyNumber
     */
    public SeededRandomTestOnly(char[] seed, byte[] scope, int keyNumber) {
        this.seed = seed;
        this.scope = scope;
        this.keyNumber = keyNumber;
    }

    @Override
    public void nextBytes(byte[] bytes) {
        PBEKeySpec spec = new PBEKeySpec(seed,
                scope,
                keyNumber, 8 * bytes.length);
        SecretKeyFactory skf = null;
        try {
            skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Algorithm Error", ex);
        }
        byte[] encoded = null;
        try {
            encoded = skf.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException ex) {
            throw new RuntimeException("KeySpecE rror", ex);
        }
        for (int i = 0; i != bytes.length; i++) {
            bytes[i] = encoded[i];
        }
    }

}
