/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.takamaka.crypto.tkmsecurityprovider.util.adaptor.v1;

/**
 *
 * @author giovanni.antino@h2tcoin.com
 */
public class RainbowCypherBeanV1 {

    private boolean valid;
    private String signature;
    private Exception ex;

    public Exception getEx() {
        return ex;
    }

    protected void setEx(Exception ex) {
        this.ex = ex;
    }

    public boolean isValid() {
        return valid;
    }

    protected void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getSignature() {
        return signature;
    }

    protected void setSignature(String signature) {
        this.signature = signature;
    }
}
