/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1.rainbowV1;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class RainbowKeyGenerationParameters
        extends KeyGenerationParameters {

    private RainbowParameters params;

    public RainbowKeyGenerationParameters(
            SecureRandom random,
            RainbowParameters params) {
        // TODO: key size?
        super(random, params.getVi()[params.getVi().length - 1] - params.getVi()[0]);
        this.params = params;
    }

    public RainbowParameters getParameters() {
        return params;
    }
}
