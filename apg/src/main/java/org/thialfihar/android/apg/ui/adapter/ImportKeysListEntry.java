/*
 * Copyright (C) 2013 Dominik Schürmann <dominik@dominikschuermann.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.thialfihar.android.apg.ui.adapter;

import android.os.Parcel;
import android.os.Parcelable;

import org.spongycastle.openpgp.PGPKeyRing;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.pgp.PgpKeyHelper;
import org.thialfihar.android.apg.util.IterableIterator;
import org.thialfihar.android.apg.util.Log;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

public class ImportKeysListEntry implements Serializable, Parcelable {
    private static final long serialVersionUID = -7797972103284992662L;
    public ArrayList<String> userIds;

    public long keyId;
    public boolean revoked;
    public Date date; // TODO: not displayed
    public String fingerPrint;
    public String hexKeyId;
    public int bitStrength;
    public String algorithm;
    public boolean secretKey;

    private byte[] mBytes = new byte[] {};
    private boolean mSelected;

    public ImportKeysListEntry(ImportKeysListEntry b) {
        userIds = b.userIds;
        keyId = b.keyId;
        revoked = b.revoked;
        date = b.date;
        fingerPrint = b.fingerPrint;
        hexKeyId = b.hexKeyId;
        bitStrength = b.bitStrength;
        algorithm = b.algorithm;
        secretKey = b.secretKey;

        mSelected = b.isSelected();
        mBytes = b.getBytes();
    }

    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeStringList(userIds);
        dest.writeLong(keyId);
        dest.writeByte((byte) (revoked ? 1 : 0));
        dest.writeSerializable(date);
        dest.writeString(fingerPrint);
        dest.writeString(hexKeyId);
        dest.writeInt(bitStrength);
        dest.writeString(algorithm);
        dest.writeByte((byte) (secretKey ? 1 : 0));
        dest.writeByte((byte) (mSelected ? 1 : 0));
        dest.writeInt(mBytes.length);
        dest.writeByteArray(mBytes);
    }

    public static final Creator<ImportKeysListEntry> CREATOR = new Creator<ImportKeysListEntry>() {
        public ImportKeysListEntry createFromParcel(final Parcel source) {
            ImportKeysListEntry vr = new ImportKeysListEntry();
            vr.userIds = new ArrayList<String>();
            source.readStringList(vr.userIds);
            vr.keyId = source.readLong();
            vr.revoked = source.readByte() == 1;
            vr.date = (Date) source.readSerializable();
            vr.fingerPrint = source.readString();
            vr.hexKeyId = source.readString();
            vr.bitStrength = source.readInt();
            vr.algorithm = source.readString();
            vr.secretKey = source.readByte() == 1;
            vr.setSelected(source.readByte() == 1);
            vr.setBytes(new byte[source.readInt()]);
            source.readByteArray(vr.mBytes);

            return vr;
        }

        public ImportKeysListEntry[] newArray(final int size) {
            return new ImportKeysListEntry[size];
        }
    };

    public long getKeyId() {
        return keyId;
    }

    public byte[] getBytes() {
        return mBytes;
    }

    public void setBytes(byte[] bytes) {
        mBytes = bytes;
    }

    /**
     * Constructor for later querying from keyserver
     */
    public ImportKeysListEntry() {
        secretKey = false;
        userIds = new ArrayList<String>();
    }

    public boolean isSelected() {
        return mSelected;
    }

    public void setSelected(boolean selected) {
        mSelected = selected;
    }

    /**
     * Constructor based on key object, used for import from NFC, QR Codes, files
     */
    @SuppressWarnings("unchecked")
    public ImportKeysListEntry(PGPKeyRing pgpKeyRing) {
        // save actual key object into entry, used to import it later
        try {
            mBytes = pgpKeyRing.getEncoded();
        } catch (IOException e) {
            Log.e(Constants.TAG, "IOException on pgpKeyRing.getEncoded()", e);
        }

        // selected is default
        mSelected = true;

        if (pgpKeyRing instanceof PGPSecretKeyRing) {
            secretKey = true;
        } else {
            secretKey = false;
        }

        userIds = new ArrayList<String>();
        for (String userId : new IterableIterator<String>(pgpKeyRing.getPublicKey().getUserIDs())) {
            userIds.add(userId);
        }
        keyId = pgpKeyRing.getPublicKey().getKeyID();

        revoked = pgpKeyRing.getPublicKey().isRevoked();
        fingerPrint = PgpKeyHelper.convertFingerprintToHex(pgpKeyRing.getPublicKey()
                .getFingerprint(), true);
        hexKeyId = "0x" + PgpKeyHelper.convertKeyIdToHex(keyId);
        bitStrength = pgpKeyRing.getPublicKey().getBitStrength();
        int algorithmId = pgpKeyRing.getPublicKey().getAlgorithm();
        if (algorithmId == PGPPublicKey.RSA_ENCRYPT ||
            algorithmId == PGPPublicKey.RSA_GENERAL ||
            algorithmId == PGPPublicKey.RSA_SIGN) {
            algorithm = "RSA";
        } else if (algorithmId == PGPPublicKey.DSA) {
            algorithm = "DSA";
        } else if (algorithmId == PGPPublicKey.ELGAMAL_ENCRYPT ||
                   algorithmId == PGPPublicKey.ELGAMAL_GENERAL) {
            algorithm = "ElGamal";
        } else if (algorithmId == PGPPublicKey.EC ||
                   algorithmId == PGPPublicKey.ECDSA) {
            algorithm = "ECC";
        } else {
            // TODO: with resources
            algorithm = "unknown";
        }
    }
}
