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

package org.thialfihar.android.apg.ui.widget;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.support.v7.app.ActionBarActivity;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.beardedhen.androidbootstrap.BootstrapButton;

import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.pgp.Key;
import org.thialfihar.android.apg.service.ApgIntentService;
import org.thialfihar.android.apg.service.ApgIntentServiceHandler;
import org.thialfihar.android.apg.service.PassphraseCacheService;
import org.thialfihar.android.apg.ui.dialog.CreateKeyDialogFragment;
import org.thialfihar.android.apg.ui.dialog.ProgressDialogFragment;
import org.thialfihar.android.apg.ui.widget.Editor.EditorListener;
import org.thialfihar.android.apg.util.Choice;

import java.util.Vector;

public class SectionView extends LinearLayout implements OnClickListener, EditorListener {
    private LayoutInflater mInflater;
    private BootstrapButton mPlusButton;
    private ViewGroup mEditors;
    private TextView mTitle;
    private int mType = 0;

    private Choice mNewKeyAlgorithmChoice;
    private int mNewKeySize;
    private boolean mCanBeEdited = true;

    private ActionBarActivity mActivity;

    private ProgressDialogFragment mGeneratingDialog;

    public SectionView(Context context) {
        super(context);
        mActivity = (ActionBarActivity) context;
    }

    public SectionView(Context context, AttributeSet attrs) {
        super(context, attrs);
        mActivity = (ActionBarActivity) context;
    }

    public ViewGroup getEditors() {
        return mEditors;
    }

    public void setType(int type) {
        mType = type;
        switch (type) {
        case Id.type.user_id: {
            mTitle.setText(R.string.section_user_ids);
            break;
        }

        case Id.type.key: {
            mTitle.setText(R.string.section_keys);
            break;
        }

        default: {
            break;
        }
        }
    }

    public void setCanBeEdited(boolean canBeEdited) {
        mCanBeEdited = canBeEdited;
        if (!mCanBeEdited) {
            mPlusButton.setVisibility(View.INVISIBLE);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void onFinishInflate() {
        mInflater = (LayoutInflater) getContext().getSystemService(Context.LAYOUT_INFLATER_SERVICE);

        setDrawingCacheEnabled(true);
        setAlwaysDrawnWithCacheEnabled(true);

        mPlusButton = (BootstrapButton) findViewById(R.id.plusbutton);
        mPlusButton.setOnClickListener(this);

        mEditors = (ViewGroup) findViewById(R.id.editors);
        mTitle = (TextView) findViewById(R.id.title);

        updateEditorsVisible();
        super.onFinishInflate();
    }

    /** {@inheritDoc} */
    public void onDeleted(Editor editor) {
        this.updateEditorsVisible();
    }

    protected void updateEditorsVisible() {
        final boolean hasChildren = mEditors.getChildCount() > 0;
        mEditors.setVisibility(hasChildren ? View.VISIBLE : View.GONE);
    }

    /** {@inheritDoc} */
    public void onClick(View v) {
        if (mCanBeEdited) {
            switch (mType) {
            case Id.type.user_id: {
                UserIdEditor view = (UserIdEditor) mInflater.inflate(
                        R.layout.edit_key_user_id_item, mEditors, false);
                view.setEditorListener(this);
                if (mEditors.getChildCount() == 0) {
                    view.setIsMainUserId(true);
                }
                mEditors.addView(view);
                break;
            }

            case Id.type.key: {
                CreateKeyDialogFragment mCreateKeyDialogFragment =
                    CreateKeyDialogFragment.newInstance(mEditors.getChildCount());
                mCreateKeyDialogFragment.setOnAlgorithmSelectedListener(
                    new CreateKeyDialogFragment.OnAlgorithmSelectedListener() {
                    @Override
                    public void onAlgorithmSelected(Choice algorithmChoice, int keySize) {
                        mNewKeyAlgorithmChoice = algorithmChoice;
                        mNewKeySize = keySize;
                        createKey();
                    }
                });
                mCreateKeyDialogFragment.show(mActivity.getSupportFragmentManager(), "createKeyDialog");
                break;
            }

            default: {
                break;
            }
            }
            this.updateEditorsVisible();
        }
    }

    public void setUserIds(Vector<String> list) {
        if (mType != Id.type.user_id) {
            return;
        }

        mEditors.removeAllViews();
        for (String userId : list) {
            UserIdEditor view = (UserIdEditor) mInflater.inflate(R.layout.edit_key_user_id_item,
                    mEditors, false);
            view.setEditorListener(this);
            view.setValue(userId);
            if (mEditors.getChildCount() == 0) {
                view.setIsMainUserId(true);
            }
            view.setCanBeEdited(mCanBeEdited);
            mEditors.addView(view);
        }

        this.updateEditorsVisible();
    }

    public void setKeys(Vector<Key> list, Vector<Integer> usages) {
        if (mType != Id.type.key) {
            return;
        }

        mEditors.removeAllViews();

        // go through all keys and set view based on them
        for (int i = 0; i < list.size(); i++) {
            KeyEditor view = (KeyEditor) mInflater.inflate(R.layout.edit_key_key_item, mEditors,
                    false);
            view.setEditorListener(this);
            boolean isMasterKey = (mEditors.getChildCount() == 0);
            view.setValue(list.get(i), isMasterKey, usages.get(i));
            view.setCanBeEdited(mCanBeEdited);
            mEditors.addView(view);
        }

        this.updateEditorsVisible();
    }

    private void createKey() {
        // Send all information needed to service to edit key in other thread
        final Intent intent = new Intent(mActivity, ApgIntentService.class);

        intent.setAction(ApgIntentService.ACTION_GENERATE_KEY);

        // fill values for this action
        Bundle data = new Bundle();
        Boolean isMasterKey;

        String passphrase;
        if (mEditors.getChildCount() > 0) {
            Key masterKey = ((KeyEditor) mEditors.getChildAt(0)).getValue();
            passphrase = PassphraseCacheService.getCachedPassphrase(mActivity, masterKey.getKeyId());
            isMasterKey = false;
        } else {
            passphrase = "";
            isMasterKey = true;
        }
        data.putBoolean(ApgIntentService.GENERATE_KEY_MASTER_KEY, isMasterKey);
        data.putString(ApgIntentService.GENERATE_KEY_SYMMETRIC_PASSPHRASE, passphrase);
        data.putInt(ApgIntentService.GENERATE_KEY_ALGORITHM, mNewKeyAlgorithmChoice.getId());
        data.putInt(ApgIntentService.GENERATE_KEY_KEY_SIZE, mNewKeySize);

        intent.putExtra(ApgIntentService.EXTRA_DATA, data);

        // show progress dialog
        mGeneratingDialog = ProgressDialogFragment.newInstance(R.string.progress_generating,
                ProgressDialog.STYLE_SPINNER, true, new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                mActivity.stopService(intent);
            }
        });

        // Message is received after generating is done in ApgService
        ApgIntentServiceHandler saveHandler = new ApgIntentServiceHandler(mActivity,
                mGeneratingDialog) {
            public void handleMessage(Message message) {
                // handle messages by standard ApgHandler first
                super.handleMessage(message);

                if (message.arg1 == ApgIntentServiceHandler.MESSAGE_OKAY) {
                    // get new key from data bundle returned from service
                    Bundle data = message.getData();
                    Key newKey = (Key) data.getSerializable(ApgIntentService.RESULT_NEW_KEY);
                    addGeneratedKeyToView(newKey);
                }
            };
        };

        // Create a new Messenger for the communication back
        Messenger messenger = new Messenger(saveHandler);
        intent.putExtra(ApgIntentService.EXTRA_MESSENGER, messenger);

        mGeneratingDialog.show(mActivity.getSupportFragmentManager(), "dialog");

        // start service with intent
        mActivity.startService(intent);
    }

    private void addGeneratedKeyToView(Key newKey) {
        // add view with new key
        KeyEditor view = (KeyEditor) mInflater.inflate(R.layout.edit_key_key_item,
                mEditors, false);
        view.setEditorListener(SectionView.this);
        view.setValue(newKey, newKey.isMasterKey(), -1);
        mEditors.addView(view);
        SectionView.this.updateEditorsVisible();
    }
}
