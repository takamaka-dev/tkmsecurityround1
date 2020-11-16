/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1.rainbowV1;

public class RainbowPublicKeyParameters
    extends RainbowKeyParameters
{
    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;

    /**
     * Constructor
     *
     * @param docLength
     * @param coeffQuadratic
     * @param coeffSingular
     * @param coeffScalar
     */
    public RainbowPublicKeyParameters(int docLength,
                                      short[][] coeffQuadratic, short[][] coeffSingular,
                                      short[] coeffScalar)
    {
        super(false, docLength);

        this.coeffquadratic = coeffQuadratic;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;

    }

    /**
     * @return the coeffquadratic
     */
    public short[][] getCoeffQuadratic()
    {
        return coeffquadratic;
    }

    /**
     * @return the coeffsingular
     */
    public short[][] getCoeffSingular()
    {
        return coeffsingular;
    }

    /**
     * @return the coeffscalar
     */
    public short[] getCoeffScalar()
    {
        return coeffscalar;
    }
}
