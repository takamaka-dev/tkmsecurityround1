/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1;

import org.bouncycastle.crypto.KeyGenerationParameters;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;

/**
 * Key-pair generator for qTESLA keys.
 */
public final class QTESLAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    /**
     * qTESLA Security Category
     */
    private int securityCategory;
    private SecureRandom secureRandom;

    /**
     * Initialize the generator with a security category and a source of randomness.
     *
     * @param param a {@link QTESLAKeyGenerationParameters} object.
     */
    @Override
    public void init(
        KeyGenerationParameters param)
    {
        QTESLAKeyGenerationParameters parameters = (QTESLAKeyGenerationParameters)param;

        this.secureRandom = parameters.getRandom();
        this.securityCategory = parameters.getSecurityCategory();
    }

    /**
     * Generate a key-pair.
     *
     * @return a matching key-pair consisting of (QTESLAPublicKeyParameters, QTESLAPrivateKeyParameters).
     */
    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] privateKey = allocatePrivate(securityCategory);
        byte[] publicKey = allocatePublic(securityCategory);

        switch (securityCategory)
        {
        case QTESLASecurityCategory.HEURISTIC_I:
            QTESLA.generateKeyPairI(publicKey, privateKey, secureRandom);
            break;
        case QTESLASecurityCategory.HEURISTIC_III_SIZE:
            QTESLA.generateKeyPairIIISize(publicKey, privateKey, secureRandom);
            break;
        case QTESLASecurityCategory.HEURISTIC_III_SPEED:
            QTESLA.generateKeyPairIIISpeed(publicKey, privateKey, secureRandom);
            break;
        case QTESLASecurityCategory.PROVABLY_SECURE_I:
            QTESLA.generateKeyPairIP(publicKey, privateKey, secureRandom);
            break;
        case QTESLASecurityCategory.PROVABLY_SECURE_III:
            QTESLA.generateKeyPairIIIP(publicKey, privateKey, secureRandom);
            break;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }

        return new AsymmetricCipherKeyPair(new QTESLAPublicKeyParameters(securityCategory, publicKey), new QTESLAPrivateKeyParameters(securityCategory, privateKey));
    }

    private byte[] allocatePrivate(int securityCategory)
    {
        return new byte[QTESLASecurityCategory.getPrivateSize(securityCategory)];
    }

    private byte[] allocatePublic(int securityCategory)
    {
        return new byte[QTESLASecurityCategory.getPublicSize(securityCategory)];
    }
}
