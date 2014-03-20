/*
 * Copyright (C) 2014 Dominik Schürmann <dominik@dominikschuermann.de>
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

package org.thialfihar.android.apg.helper;

import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.support.v7.app.ActionBarActivity;
import android.widget.Toast;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.compatibility.DialogFragmentWorkaround;
import org.thialfihar.android.apg.service.ApgIntentService;
import org.thialfihar.android.apg.service.ApgIntentServiceHandler;
import org.thialfihar.android.apg.ui.dialog.DeleteKeyDialogFragment;
import org.thialfihar.android.apg.ui.dialog.FileDialogFragment;
import org.thialfihar.android.apg.util.Log;

public class ExportHelper {
    protected FileDialogFragment mFileDialog;
    protected String mExportFilename;

    private ActionBarActivity mActivity;

    public ExportHelper(ActionBarActivity activity) {
        super();
        mActivity = activity;
    }

    public void deleteKey(Uri dataUri, Handler deleteHandler) {
        long keyRingRowId = Long.valueOf(dataUri.getLastPathSegment());

        // Create a new Messenger for the communication back
        Messenger messenger = new Messenger(deleteHandler);

        DeleteKeyDialogFragment deleteKeyDialog = DeleteKeyDialogFragment.newInstance(messenger,
                new long[] { keyRingRowId });

        deleteKeyDialog.show(mActivity.getSupportFragmentManager(), "deleteKeyDialog");
    }

    /**
     * Show dialog where to export keys
     */
    public void showExportKeysDialog(final long[] masterKeyIds, final int keyType,
                                     final String exportFilename, final String checkboxString) {
        mExportFilename = exportFilename;

        // Message is received after file is selected
        Handler returnHandler = new Handler() {
            @Override
            public void handleMessage(Message message) {
                if (message.what == FileDialogFragment.MESSAGE_OKAY) {
                    Bundle data = message.getData();
                    int type = keyType;
                    mExportFilename = data.getString(FileDialogFragment.MESSAGE_DATA_FILENAME);

                    if (data.getBoolean(FileDialogFragment.MESSAGE_DATA_CHECKED)) {
                        type = Id.type.public_secret_key;
                    }

                    exportKeys(masterKeyIds, type);
                }
            }
        };

        // Create a new Messenger for the communication back
        final Messenger messenger = new Messenger(returnHandler);

        DialogFragmentWorkaround.INTERFACE.runnableRunDelayed(new Runnable() {
            public void run() {
                String title = null;
                if (masterKeyIds == null) {
                    // export all keys
                    title = mActivity.getString(R.string.title_export_keys);
                } else {
                    // export only key specified at data uri
                    title = mActivity.getString(R.string.title_export_key);
                }

                String message = mActivity.getString(R.string.specify_file_to_export_to);

                mFileDialog = FileDialogFragment.newInstance(messenger, title, message,
                        exportFilename, checkboxString);

                mFileDialog.show(mActivity.getSupportFragmentManager(), "fileDialog");
            }
        });
    }

    /**
     * Export keys
     */
    public void exportKeys(long[] masterKeyIds, int keyType) {
        Log.d(Constants.TAG, "exportKeys started");

        // Send all information needed to service to export key in other thread
        final Intent intent = new Intent(mActivity, ApgIntentService.class);

        intent.setAction(ApgIntentService.ACTION_EXPORT_KEYRING);

        // fill values for this action
        Bundle data = new Bundle();

        data.putString(ApgIntentService.EXPORT_FILENAME, mExportFilename);
        data.putInt(ApgIntentService.EXPORT_KEY_TYPE, keyType);

        if (masterKeyIds == null) {
            data.putBoolean(ApgIntentService.EXPORT_ALL, true);
        } else {
            data.putLongArray(ApgIntentService.EXPORT_KEY_RING_MASTER_KEY_ID, masterKeyIds);
        }

        intent.putExtra(ApgIntentService.EXTRA_DATA, data);

        // Message is received after exporting is done in ApgService
        ApgIntentServiceHandler exportHandler = new ApgIntentServiceHandler(mActivity,
                mActivity.getString(R.string.progress_exporting),
                ProgressDialog.STYLE_HORIZONTAL, true, new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialogInterface) {
                mActivity.stopService(intent);
            }
        }) {
            public void handleMessage(Message message) {
                // handle messages by standard ApgHandler first
                super.handleMessage(message);

                if (message.arg1 == ApgIntentServiceHandler.MESSAGE_OKAY) {
                    // get returned data bundle
                    Bundle returnData = message.getData();

                    int exported = returnData.getInt(ApgIntentService.RESULT_EXPORT);
                    String toastMessage;
                    if (exported == 1) {
                        toastMessage = mActivity.getString(R.string.key_exported);
                    } else if (exported > 0) {
                        toastMessage = mActivity.getString(R.string.keys_exported, exported);
                    } else {
                        toastMessage = mActivity.getString(R.string.no_keys_exported);
                    }
                    Toast.makeText(mActivity, toastMessage, Toast.LENGTH_SHORT).show();

                }
            }
        };

        // Create a new Messenger for the communication back
        Messenger messenger = new Messenger(exportHandler);
        intent.putExtra(ApgIntentService.EXTRA_MESSENGER, messenger);

        // show progress dialog
        exportHandler.showProgressDialog(mActivity);

        // start service with intent
        mActivity.startService(intent);
    }

}
