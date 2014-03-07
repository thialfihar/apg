package org.thialfihar.android.apg.service.remote;

public class WrongPackageSignatureException extends Exception {

    private static final long serialVersionUID = -8294642703122196028L;

    public WrongPackageSignatureException(String message) {
        super(message);
    }
}
