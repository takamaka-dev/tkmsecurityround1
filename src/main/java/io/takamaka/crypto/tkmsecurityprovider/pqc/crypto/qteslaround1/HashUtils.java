/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1;

import io.takamaka.crypto.digests.CSHAKEDigest;
import io.takamaka.crypto.digests.SHAKEDigest;

class HashUtils {

    public static final int SECURE_HASH_ALGORITHM_KECCAK_128_RATE = 168;
    public static final int SECURE_HASH_ALGORITHM_KECCAK_256_RATE = 136;

    /**
     * *************************************************************************************************************************************************************
     * Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That
     * Generally Supports 128 Bits of Security Strength, If the Output is
     * Sufficiently Long
     **************************************************************************************************************************************************************
     */
    static void secureHashAlgorithmKECCAK128(byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength) {
        SHAKEDigest dig = new SHAKEDigest(128);
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

    /**
     * *************************************************************************************************************************************************************
     * Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That
     * Generally Supports 256 Bits of Security Strength, If the Output is
     * Sufficiently Long
     **************************************************************************************************************************************************************
     */
    static void secureHashAlgorithmKECCAK256(byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength) {
        SHAKEDigest dig = new SHAKEDigest(256);
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

    /* Customizable Secure Hash Algorithm KECCAK 128 / Customizable Secure Hash Algorithm KECCAK 256 */
    static void customizableSecureHashAlgorithmKECCAK128Simple(byte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength) {
        CSHAKEDigest dig = new CSHAKEDigest(128, null, new byte[]{(byte) continuousTimeStochasticModelling, (byte) (continuousTimeStochasticModelling >> 8)});
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

    static void customizableSecureHashAlgorithmKECCAK256Simple(byte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength) {
        CSHAKEDigest dig = new CSHAKEDigest(256, null, new byte[]{(byte) continuousTimeStochasticModelling, (byte) (continuousTimeStochasticModelling >> 8)});
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }
}
