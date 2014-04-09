/*
 * Copyright (C) 2010-2014 Thialfihar <thi@thialfihar.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.thialfihar.android.apg.pgp;

import android.content.Context;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.PGPKeyRing;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;

import org.sufficientlysecure.keychain.util.IterableIterator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

public class KeyRing {
    private PGPSecretKeyRing mSecretKeyRing;
    private PGPPublicKeyRing mPublicKeyRing;

    public static KeyRing decode(byte[] data) {
        PGPObjectFactory factory = new PGPObjectFactory(data);
        KeyRing keyRing = null;
        try {
            Object obj = factory.nextObject();
            if (obj == null) {
                return null;
            } else if (obj instanceof PGPPublicKeyRing) {
                keyRing = new PublicKeyRing((PGPPublicKeyRing) obj);
            } else if (obj instanceof PGPSecretKeyRing) {
                keyRing = new SecretKeyRing((PGPSecretKeyRing) obj);
            }
        } catch (IOException e) {
            return null;
        }

        return keyRing;
    }

    public KeyRing(PGPKeyRing keyRing) {
        if (keyRing instanceof PGPPublicKeyRing) {
            mPublicKeyRing = (PGPPublicKeyRing) keyRing;
        } else {
            mSecretKeyRing = (PGPSecretKeyRing) keyRing;
        }
    }

    public KeyRing(PGPPublicKeyRing publicKeyRing) {
        mPublicKeyRing = publicKeyRing;
    }

    public KeyRing(PGPSecretKeyRing secretKeyRing) {
        mSecretKeyRing = secretKeyRing;
    }

    public boolean isPublic() {
        if (mPublicKeyRing != null) {
            return true;
        }
        return false;
    }

    public PGPPublicKeyRing getPublicKeyRing() {
        return mPublicKeyRing;
    }

    public PGPSecretKeyRing getSecretKeyRing() {
        return mSecretKeyRing;
    }

    public Key getSecretKey(long keyId) {
        if (isPublic()) {
            return null;
        }
        return new Key(mSecretKeyRing.getSecretKey(keyId));
    }

    public Key getPublicKey(long keyId) {
        return new Key(mPublicKeyRing.getPublicKey(keyId));
    }

    public byte[] getEncoded() throws IOException {
        if (isPublic()) {
            return mPublicKeyRing.getEncoded();
        }
        return mSecretKeyRing.getEncoded();
    }

    public String getArmoredEncoded(Context context) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ArmoredOutputStream aos = new ArmoredOutputStream(bos);
        aos.setHeader("Version", PgpHelper.getFullVersion(context));
        aos.write(getEncoded());
        aos.close();

        return bos.toString("UTF-8");
    }

    public ArrayList<Key> getPublicKeys() {
        ArrayList<Key> keys = new ArrayList<Key>();
        for (PGPPublicKey key : new IterableIterator<PGPPublicKey>(mPublicKeyRing.getPublicKeys())) {
            keys.add(new Key(key));
        }
        return keys;
    }

    public ArrayList<Key> getSecretKeys() {
        ArrayList<Key> keys = new ArrayList<Key>();
        if (isPublic()) {
            return keys;
        }
        for (PGPSecretKey key : new IterableIterator<PGPSecretKey>(mSecretKeyRing.getSecretKeys())) {
            keys.add(new Key(key));
        }
        return keys;
    }

    public Key getMasterKey() {
        if (isPublic()) {
            for (Key key : getPublicKeys()) {
                if (key.isMasterKey()) {
                    return key;
                }
            }

            return null;
        } else {
            for (Key key : getSecretKeys()) {
                if (key.isMasterKey()) {
                    return key;
                }
            }

            return null;
        }
    }

    public ArrayList<Key> getEncryptKeys() {
        ArrayList<Key> encryptKeys = new ArrayList<Key>();
        for (Key key : getPublicKeys()) {
            if (key.isEncryptionKey()) {
                encryptKeys.add(key);
            }
        }

        return encryptKeys;
    }

    public ArrayList<Key> getSigningKeys() {
        ArrayList<Key> signingKeys = new ArrayList<Key>();
        for (Key key : getSecretKeys()) {
            if (key.isSigningKey()) {
                signingKeys.add(key);
            }
        }

        return signingKeys;
    }

    public ArrayList<Key> getUsableEncryptKeys() {
        ArrayList<Key> usableKeys = new ArrayList<Key>();
        ArrayList<Key> encryptKeys = getEncryptKeys();
        Key masterKey = null;
        for (int i = 0; i < encryptKeys.size(); ++i) {
            Key key = encryptKeys.get(i);
            if (!key.isExpired()) {
                if (key.isMasterKey()) {
                    masterKey = key;
                } else {
                    usableKeys.add(key);
                }
            }
        }
        if (masterKey != null) {
            usableKeys.add(masterKey);
        }
        return usableKeys;
    }

    public ArrayList<Key> getUsableSigningKeys() {
        ArrayList<Key> usableKeys = new ArrayList<Key>();
        ArrayList<Key> signingKeys = getSigningKeys();
        Key masterKey = null;
        for (int i = 0; i < signingKeys.size(); ++i) {
            Key key = signingKeys.get(i);
            if (key.isMasterKey()) {
                masterKey = key;
            } else {
                usableKeys.add(key);
            }
        }
        if (masterKey != null) {
            usableKeys.add(masterKey);
        }
        return usableKeys;
    }


    public Key getSigningKey() {
        for (Key key : getUsableSigningKeys()) {
            return key;
        }
        return null;
    }

    public Key getEncryptKey() {
        for (Key key : getUsableEncryptKeys()) {
            return key;
        }
        return null;
    }
}
