/*
 * Copyright (C) 2013-2014 Dominik Schürmann <dominik@dominikschuermann.de>
 * Copyright (C) 2013 Bahtiar 'kalkin' Gadimov
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

package org.thialfihar.android.apg.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v4.view.ViewPager;
import android.support.v7.app.ActionBar;
import android.support.v7.app.ActionBarActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.Window;
import android.widget.Toast;

import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.Id;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.compatibility.ClipboardReflection;
import org.sufficientlysecure.keychain.helper.ExportHelper;
import org.sufficientlysecure.keychain.pgp.KeyRing;
import org.sufficientlysecure.keychain.pgp.PgpKeyHelper;
import org.sufficientlysecure.keychain.provider.KeychainContract;
import org.sufficientlysecure.keychain.provider.ProviderHelper;
import org.sufficientlysecure.keychain.ui.adapter.TabsAdapter;
import org.sufficientlysecure.keychain.ui.dialog.ShareNfcDialogFragment;
import org.sufficientlysecure.keychain.ui.dialog.ShareQrCodeDialogFragment;
import org.sufficientlysecure.keychain.util.Log;

import java.io.IOException;

public class ViewKeyActivity extends ActionBarActivity {

    ExportHelper mExportHelper;
    ProviderHelper mProvider;

    protected Uri mDataUri;

    public static final String EXTRA_SELECTED_TAB = "selectedTab";

    ViewPager mViewPager;
    TabsAdapter mTabsAdapter;

    private static final int RESULT_CODE_LOOKUP_KEY = 0x00007006;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
        super.onCreate(savedInstanceState);

        mExportHelper = new ExportHelper(this);
        mProvider = new ProviderHelper(this);

        // let the actionbar look like Android's contact app
        ActionBar actionBar = getSupportActionBar();
        actionBar.setDisplayHomeAsUpEnabled(true);
        actionBar.setIcon(android.R.color.transparent);
        actionBar.setHomeButtonEnabled(true);
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

        setContentView(R.layout.view_key_activity);

        mViewPager = (ViewPager) findViewById(R.id.pager);

        mTabsAdapter = new TabsAdapter(this, mViewPager);

        int selectedTab = 0;
        Intent intent = getIntent();
        if (intent.getExtras() != null && intent.getExtras().containsKey(EXTRA_SELECTED_TAB)) {
            selectedTab = intent.getExtras().getInt(EXTRA_SELECTED_TAB);
        }

        mDataUri = getIntent().getData();

        Bundle mainBundle = new Bundle();
        mainBundle.putParcelable(ViewKeyMainFragment.ARG_DATA_URI, mDataUri);
        mTabsAdapter.addTab(actionBar.newTab().setText(getString(R.string.key_view_tab_main)),
                ViewKeyMainFragment.class, mainBundle, (selectedTab == 0));

        Bundle certBundle = new Bundle();
        certBundle.putLong(ViewKeyCertsFragment.ARG_KEYRING_ROW_ID, rowId);
        mTabsAdapter.addTab(actionBar.newTab().setText(getString(R.string.key_view_tab_certs)),
                ViewKeyCertsFragment.class, certBundle, (selectedTab == 1));
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        getMenuInflater().inflate(R.menu.key_view, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                Intent homeIntent = new Intent(this, KeyListActivity.class);
                homeIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivity(homeIntent);
                return true;
            case R.id.menu_key_view_update:
                updateFromKeyserver(mDataUri);
                return true;
            case R.id.menu_key_view_export_keyserver:
                uploadToKeyserver(mDataUri);
                return true;
            case R.id.menu_key_view_export_file:
                long masterKeyId = Long.valueOf(mDataUri.getLastPathSegment());
                long[] ids = new long[]{masterKeyId};
                mExportHelper.showExportKeysDialog(ids, Id.type.public_key,
                        Constants.Path.APP_DIR_FILE_PUB, null);
                return true;
            case R.id.menu_key_view_share_default_fingerprint:
                shareKey(mDataUri, true);
                return true;
            case R.id.menu_key_view_share_default:
                shareKey(mDataUri, false);
                return true;
            case R.id.menu_key_view_share_qr_code_fingerprint:
                shareKeyQrCode(mDataUri, true);
                return true;
            case R.id.menu_key_view_share_qr_code:
                shareKeyQrCode(mDataUri, false);
                return true;
            case R.id.menu_key_view_share_nfc:
                shareNfc();
                return true;
            case R.id.menu_key_view_share_clipboard:
                copyToClipboard(mDataUri);
                return true;
            case R.id.menu_key_view_delete: {
                deleteKey(mDataUri);
                return true;
            }
        }
        return super.onOptionsItemSelected(item);
    }

    private void uploadToKeyserver(Uri dataUri) {
        Intent uploadIntent = new Intent(this, UploadKeyActivity.class);
        uploadIntent.setData(dataUri);
        startActivityForResult(uploadIntent, Id.request.export_to_server);
    }

    private void updateFromKeyserver(Uri dataUri) {
        byte[] blob = (byte[]) ProviderHelper.getGenericData(
                this, KeychainContract.KeyRings.buildUnifiedKeyRingUri(dataUri),
                KeychainContract.Keys.FINGERPRINT, ProviderHelper.FIELD_TYPE_BLOB);
        String fingerprint = PgpKeyHelper.convertFingerprintToHex(blob);

        Intent queryIntent = new Intent(this, ImportKeysActivity.class);
        queryIntent.setAction(ImportKeysActivity.ACTION_IMPORT_KEY_FROM_KEYSERVER_AND_RETURN);
        queryIntent.putExtra(ImportKeysActivity.EXTRA_FINGERPRINT, fingerprint);

        startActivityForResult(queryIntent, RESULT_CODE_LOOKUP_KEY);
    }

    private void shareKey(Uri dataUri, boolean fingerprintOnly) {
        String content;
        if (fingerprintOnly) {
            byte[] data = (byte[]) ProviderHelper.getGenericData(
                    this, KeychainContract.KeyRings.buildUnifiedKeyRingUri(dataUri),
                    KeychainContract.Keys.FINGERPRINT, ProviderHelper.FIELD_TYPE_BLOB);
            if(data != null) {
                String fingerprint = PgpKeyHelper.convertFingerprintToHex(data);
                content = Constants.FINGERPRINT_SCHEME + ":" + fingerprint;
            } else {
                Toast.makeText(getApplicationContext(), "Bad key selected!",
                        Toast.LENGTH_LONG).show();
                return;
            }
        } else {
            // get public keyring as ascii armored string
            long masterKeyId = ProviderHelper.getMasterKeyId(this, dataUri);
            ArrayList<String> keyringArmored = ProviderHelper.getKeyRingsAsArmoredString(
                    this, new long[]{ masterKeyId });

            content = keyringArmored.get(0);

            // Android will fail with android.os.TransactionTooLargeException if key is too big
            // see http://www.lonestarprod.com/?p=34
            if (content.length() >= 86389) {
                Toast.makeText(getApplicationContext(), R.string.key_too_big_for_sharing,
                        Toast.LENGTH_LONG).show();
                return;
            }
        }

        // let user choose application
        Intent sendIntent = new Intent(Intent.ACTION_SEND);
        sendIntent.putExtra(Intent.EXTRA_TEXT, content);
        sendIntent.setType("text/plain");
        startActivity(Intent.createChooser(sendIntent,
                getResources().getText(R.string.action_share_key_with)));
    }

    private void shareKeyQrCode(Uri dataUri, boolean fingerprintOnly) {
        ShareQrCodeDialogFragment dialog = ShareQrCodeDialogFragment.newInstance(dataUri,
                fingerprintOnly);
        dialog.show(getSupportFragmentManager(), "shareQrCodeDialog");
    }

    private void copyToClipboard(Uri dataUri) {
        // get public keyring as ascii armored string
        long masterKeyId = ProviderHelper.getMasterKeyId(this, dataUri);
        KeyRing keyRing = mProvider.getPublicKeyRingByMasterKeyId(masterKeyId);
        String armoredKeyRing;
        try {
            armoredKeyRing = keyRing.getArmoredEncoded(this);
        } catch (IOException e) {
            Toast.makeText(getApplicationContext(), R.string.error_could_not_encode_key_ring,
                    Toast.LENGTH_LONG).show();
            return;
        }

        ClipboardReflection.copyToClipboard(this, armoredKeyRing);
        Toast.makeText(getApplicationContext(), R.string.key_copied_to_clipboard, Toast.LENGTH_LONG)
                .show();
    }

    private void shareNfc() {
        ShareNfcDialogFragment dialog = ShareNfcDialogFragment.newInstance();
        dialog.show(getSupportFragmentManager(), "shareNfcDialog");
    }

    private void deleteKey(Uri dataUri) {
        // Message is received after key is deleted
        Handler returnHandler = new Handler() {
            @Override
            public void handleMessage(Message message) {
                setResult(RESULT_CANCELED);
                finish();
            }
        };

        mExportHelper.deleteKey(dataUri, returnHandler);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case RESULT_CODE_LOOKUP_KEY: {
                if (resultCode == Activity.RESULT_OK) {
                    // TODO: reload key??? move this into fragment?
                }
                break;
            }

            default: {
                super.onActivityResult(requestCode, resultCode, data);

                break;
            }
        }
    }
}
