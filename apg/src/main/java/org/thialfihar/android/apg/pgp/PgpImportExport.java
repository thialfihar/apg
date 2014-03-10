/*
 * Copyright (C) 2012-2013 Dominik Schürmann <dominik@dominikschuermann.de>
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
import android.os.Bundle;
import android.os.Environment;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPKeyRing;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.pgp.KeyServer.AddKeyException;
import org.thialfihar.android.apg.pgp.exception.PgpGeneralException;
import org.thialfihar.android.apg.provider.ProviderHelper;
import org.thialfihar.android.apg.service.ApgIntentService;
import org.thialfihar.android.apg.ui.adapter.ImportKeysListEntry;
import org.thialfihar.android.apg.util.IterableIterator;
import org.thialfihar.android.apg.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class PgpImportExport {
    private Context mContext;
    private Progressable mProgress;

    public PgpImportExport(Context context, Progressable progress) {
        super();
        this.mContext = context;
        this.mProgress = progress;
    }

    public void updateProgress(int message, int current, int total) {
        if (mProgress != null) {
            mProgress.setProgress(message, current, total);
        }
    }

    public void updateProgress(String message, int current, int total) {
        if (mProgress != null) {
            mProgress.setProgress(message, current, total);
        }
    }

    public void updateProgress(int current, int total) {
        if (mProgress != null) {
            mProgress.setProgress(current, total);
        }
    }

    public boolean uploadKeyRingToServer(KeyServer server, PublicKeyRing keyRing) {
        try {
            server.add(keyRing.getArmoredEncoded(mContext));

            return true;
        } catch (IOException e) {
            return false;
        } catch (AddKeyException e) {
            // TODO: tell the user?
            return false;
        }
    }

    /**
     * Imports keys from given data. If keyIds is given only those are imported
     */
    public Bundle importKeyRings(List<ImportKeysListEntry> entries)
            throws PgpGeneralException, PGPException, IOException {
        Bundle returnData = new Bundle();

        updateProgress(R.string.progress_importing, 0, 100);

        int newKeys = 0;
        int oldKeys = 0;
        int badKeys = 0;

        int position = 0;
        try {
            for (ImportKeysListEntry entry : entries) {
                KeyRing obj = KeyRing.decode(entry.getBytes());

                if (obj.isPublic()) {
                    PGPKeyRing keyRing = obj.getPublicKeyRing();

                    int status = storeKeyRingInCache(keyRing);

                    if (status == Id.return_value.error) {
                        throw new PgpGeneralException(
                                mContext.getString(R.string.error_saving_keys));
                    }

                    // update the counts to display to the user at the end
                    if (status == Id.return_value.updated) {
                        ++oldKeys;
                    } else if (status == Id.return_value.ok) {
                        ++newKeys;
                    } else if (status == Id.return_value.bad) {
                        ++badKeys;
                    }
                } else {
                    Log.e(Constants.TAG, "Object not recognized as PGPKeyRing!");
                }

                position++;
                updateProgress(position / entries.size() * 100, 100);
            }
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception on parsing key file!", e);
        }

        returnData.putInt(ApgIntentService.RESULT_IMPORT_ADDED, newKeys);
        returnData.putInt(ApgIntentService.RESULT_IMPORT_UPDATED, oldKeys);
        returnData.putInt(ApgIntentService.RESULT_IMPORT_BAD, badKeys);

        return returnData;
    }

    public Bundle exportKeyRings(ArrayList<Long> keyRingMasterKeyIds, int keyType,
                                 OutputStream outStream) throws PgpGeneralException, FileNotFoundException,
            PGPException, IOException {
        Bundle returnData = new Bundle();

        updateProgress(
                mContext.getResources().getQuantityString(R.plurals.progress_exporting_key,
                        keyRingMasterKeyIds.size()), 0, 100);

        if (!Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
            throw new PgpGeneralException(
                    mContext.getString(R.string.error_external_storage_not_ready));
        }

        if (keyType == Id.type.secret_key) {
            ArmoredOutputStream outSec = new ArmoredOutputStream(outStream);
            outSec.setHeader("Version", PgpHelper.getFullVersion(mContext));

            for (int i = 0; i < keyRingMasterKeyIds.size(); ++i) {
                updateProgress(i * 100 / keyRingMasterKeyIds.size() / 2, 100);

                PGPSecretKeyRing secretKeyRing = ProviderHelper.getPGPSecretKeyRingByMasterKeyId(
                        mContext, keyRingMasterKeyIds.get(i));

                if (secretKeyRing != null) {
                    secretKeyRing.encode(outSec);
                }
            }
            outSec.close();
        } else {
            // export public keyrings...
            ArmoredOutputStream outPub = new ArmoredOutputStream(outStream);
            outPub.setHeader("Version", PgpHelper.getFullVersion(mContext));

            for (int i = 0; i < keyRingMasterKeyIds.size(); ++i) {
                // double the needed time if exporting both public and secret parts
                if (keyType == Id.type.secret_key) {
                    updateProgress(i * 100 / keyRingMasterKeyIds.size() / 2, 100);
                } else {
                    updateProgress(i * 100 / keyRingMasterKeyIds.size(), 100);
                }

                PGPPublicKeyRing publicKeyRing = ProviderHelper.getPGPPublicKeyRingByMasterKeyId(
                        mContext, keyRingMasterKeyIds.get(i));

                if (publicKeyRing != null) {
                    publicKeyRing.encode(outPub);
                }
            }
            outPub.close();
        }

        returnData.putInt(ApgIntentService.RESULT_EXPORT, keyRingMasterKeyIds.size());

        updateProgress(R.string.progress_done, 100, 100);

        return returnData;
    }

    /**
     * TODO: implement Id.return_value.updated as status when key already existed
     */
    @SuppressWarnings("unchecked")
    public int storeKeyRingInCache(PGPKeyRing keyRing) {
        int status = Integer.MIN_VALUE; // out of bounds value (Id.return_value.*)
        try {
            if (keyRing instanceof PGPSecretKeyRing) {
                PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing) keyRing;
                boolean save = true;

                for (PGPSecretKey testSecretKey : new IterableIterator<PGPSecretKey>(
                        secretKeyRing.getSecretKeys())) {
                    if (!testSecretKey.isMasterKey()) {
                        if (PgpKeyHelper.isSecretKeyPrivateEmpty(testSecretKey)) {
                            // this is bad, something is very wrong...
                            save = false;
                            status = Id.return_value.bad;
                        }
                    }
                }

                if (save) {
                    ProviderHelper.saveKeyRing(mContext, secretKeyRing);
                    // TODO: preserve certifications
                    // (http://osdir.com/ml/encryption.bouncy-castle.devel/2007-01/msg00054.html ?)
                    PGPPublicKeyRing newPubRing = null;
                    for (PGPPublicKey key : new IterableIterator<PGPPublicKey>(
                            secretKeyRing.getPublicKeys())) {
                        if (newPubRing == null) {
                            newPubRing = new PGPPublicKeyRing(key.getEncoded(),
                                    new JcaKeyFingerprintCalculator());
                        }
                        newPubRing = PGPPublicKeyRing.insertPublicKey(newPubRing, key);
                    }
                    if (newPubRing != null) {
                        ProviderHelper.saveKeyRing(mContext, newPubRing);
                    }
                    // TODO: remove status returns, use exceptions!
                    status = Id.return_value.ok;
                }
            } else if (keyRing instanceof PGPPublicKeyRing) {
                PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) keyRing;
                ProviderHelper.saveKeyRing(mContext, publicKeyRing);
                // TODO: remove status returns, use exceptions!
                status = Id.return_value.ok;
            }
        } catch (IOException e) {
            status = Id.return_value.error;
        }

        return status;
    }

}
