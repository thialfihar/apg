/*
 * Copyright (C) 2012-2014 Dominik Schürmann <dominik@dominikschuermann.de>
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

package org.thialfihar.android.apg.ui.dialog;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import com.devspark.appmsg.AppMsg;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.pgp.PgpKeyHelper;
import org.thialfihar.android.apg.provider.ApgContract.KeyRings;
import org.thialfihar.android.apg.provider.ApgContract;
import org.thialfihar.android.apg.provider.ProviderHelper;
import org.thialfihar.android.apg.util.Log;
import org.thialfihar.android.apg.util.QrCodeUtils;

public class ShareQrCodeDialogFragment extends DialogFragment {
    private static final String ARG_KEY_URI = "uri";

    private Context mContext;
    private ProviderHelper mProvider;

    private ImageView mImage;
    private TextView mText;

    private static final int QR_CODE_SIZE = 1000;

    /**
     * Creates new instance of this dialog fragment
     */
    public static ShareQrCodeDialogFragment newInstance(Uri dataUri) {
        ShareQrCodeDialogFragment frag = new ShareQrCodeDialogFragment();
        Bundle args = new Bundle();
        args.putParcelable(ARG_KEY_URI, dataUri);

        frag.setArguments(args);

        return frag;
    }

    /**
     * Creates dialog
     */
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        mContext = getActivity();
        mProvider = new ProviderHelper(mContext);

        Uri dataUri = getArguments().getParcelable(ARG_KEY_URI);

        AlertDialog.Builder alert = new AlertDialog.Builder(getActivity());
        alert.setTitle(R.string.share_qr_code_dialog_title);

        LayoutInflater inflater = getActivity().getLayoutInflater();
        View view = inflater.inflate(R.layout.share_qr_code_dialog, null);
        alert.setView(view);

        mImage = (ImageView) view.findViewById(R.id.share_qr_code_dialog_image);
        mText = (TextView) view.findViewById(R.id.share_qr_code_dialog_text);

        ProviderHelper providerHelper = new ProviderHelper(getActivity());
        String content;
        try {
            alert.setPositiveButton(R.string.btn_okay, null);

            byte[] blob = (byte[]) providerHelper.getGenericData(
                    KeyRings.buildUnifiedKeyRingUri(dataUri),
                    KeyRings.FINGERPRINT, ProviderHelper.FIELD_TYPE_BLOB);
            if (blob == null) {
                Log.e(Constants.TAG, "key not found!");
                AppMsg.makeText(getActivity(), R.string.error_key_not_found, AppMsg.STYLE_ALERT).show();
                return null;
            }

            String fingerprint = PgpKeyHelper.convertFingerprintToHex(blob);
            mText.setText(getString(R.string.share_qr_code_dialog_fingerprint_text) + " " + fingerprint);
            content = Constants.FINGERPRINT_SCHEME + ":" + fingerprint;
            setQrCode(content);
        } catch (ProviderHelper.NotFoundException e) {
            Log.e(Constants.TAG, "key not found!", e);
            AppMsg.makeText(getActivity(), R.string.error_key_not_found, AppMsg.STYLE_ALERT).show();
            return null;
        }

        return alert.create();
    }

    private void setQrCode(String data) {
        mImage.setImageBitmap(QrCodeUtils.getQRCodeBitmap(data, QR_CODE_SIZE));
    }

}
