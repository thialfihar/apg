/*
 * Copyright (C) 2012-2014 Dominik Schürmann <dominik@dominikschuermann.de>
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

import org.openintents.openpgp.OpenPgpSignatureResult;
import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.SignatureSubpacketTags;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPOnePassSignature;
import org.spongycastle.openpgp.PGPOnePassSignatureList;
import org.spongycastle.openpgp.PGPPBEEncryptedData;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyEncryptedData;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.PGPSignatureSubpacketVector;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.spongycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.spongycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.pgp.exception.PgpGeneralException;
import org.thialfihar.android.apg.service.PassphraseCacheService;
import org.thialfihar.android.apg.util.InputData;
import org.thialfihar.android.apg.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.Iterator;

/**
 * This class uses a Builder pattern!
 */
public class PgpDecryptVerify {
    private Context mContext;
    private InputData mData;
    private OutputStream mOutputStream;
    private PgpKeyProvider mKeyProvider;

    private Progressable mProgressable;
    private boolean mAssumeSymmetric;
    private String mPassphrase;
    private long mEnforcedKeyId;

    private PgpDecryptVerify(Builder builder) {
        // private Constructor can only be called from Builder
        mContext = builder.mContext;
        mData = builder.mData;
        mOutputStream = builder.mOutputStream;
        mKeyProvider = builder.mKeyProvider;

        mProgressable = builder.mProgressable;
        mAssumeSymmetric = builder.mAssumeSymmetric;
        mPassphrase = builder.mPassphrase;
        mEnforcedKeyId = builder.mEnforcedKeyId;
    }

    public static class Builder {
        // mandatory parameter
        private Context mContext;
        private InputData mData;
        private OutputStream mOutputStream;
        private PgpKeyProvider mKeyProvider;

        // optional
        private Progressable mProgressable = null;
        private boolean mAssumeSymmetric = false;
        private String mPassphrase = "";
        private long mEnforcedKeyId = 0;

        public Builder(Context context, InputData data, OutputStream outputStream,
                        PgpKeyProvider keyProvider) {
            mContext = context;
            mData = data;
            mOutputStream = outputStream;
            mKeyProvider = keyProvider;
        }

        public Builder setProgressable(Progressable progressable) {
            mProgressable = progressable;
            return this;
        }

        public Builder setAssumeSymmetric(boolean assumeSymmetric) {
            mAssumeSymmetric = assumeSymmetric;
            return this;
        }

        public Builder setPassphrase(String passphrase) {
            mPassphrase = passphrase;
            return this;
        }

        /**
         * Allow this key id alone for decryption.
         * This means only ciphertexts encrypted for this private key can be decrypted.
         *
         * @param mEnforcedKeyId
         * @return
         */
        public Builder setEnforcedKeyId(long enforcedKeyId) {
            mEnforcedKeyId = enforcedKeyId;
            return this;
        }

        public PgpDecryptVerify build() {
            return new PgpDecryptVerify(this);
        }
    }

    public void updateProgress(int message, int current, int total) {
        if (mProgressable != null) {
            mProgressable.setProgress(message, current, total);
        }
    }

    public void updateProgress(int current, int total) {
        if (mProgressable != null) {
            mProgressable.setProgress(current, total);
        }
    }

    public static boolean hasSymmetricEncryption(Context mContext, InputStream inputStream)
            throws PgpGeneralException, IOException {
        InputStream in = PGPUtil.getDecoderStream(inputStream);
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        // the first object might be a PGP marker packet.
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new PgpGeneralException(mContext.getString(R.string.error_invalid_data));
        }

        Iterator<?> it = enc.getEncryptedDataObjects();
        while (it.hasNext()) {
            Object obj = it.next();
            if (obj instanceof PGPPBEEncryptedData) {
                return true;
            }
        }

        return false;
    }

    /**
     * Decrypts and/or verifies mData based on parameters of class
     *
     * @return
     * @throws IOException
     * @throws PgpGeneralException
     * @throws PGPException
     * @throws SignatureException
     */
    public PgpDecryptVerifyResult execute()
            throws IOException, PgpGeneralException, PGPException, SignatureException {
        // automatically works with ascii armor input and binary
        InputStream in = PGPUtil.getDecoderStream(mData.getInputStream());
        if (in instanceof ArmoredInputStream) {
            ArmoredInputStream aIn = (ArmoredInputStream) in;
            // it is ascii armored
            Log.d(Constants.TAG, "ASCII Armor Header Line: " + aIn.getArmorHeaderLine());

            if (aIn.isClearText()) {
                // a cleartext signature, verify it with the other method
                return verifyCleartextSignature(aIn);
            }
            // else: ascii armored encryption! go on...
        }

        return decryptVerify(in);
    }

    /**
     * Decrypt and/or verifies binary or ascii armored pgp
     *
     * @param in
     * @return
     * @throws IOException
     * @throws PgpGeneralException
     * @throws PGPException
     * @throws SignatureException
     */
    private PgpDecryptVerifyResult decryptVerify(InputStream in)
            throws IOException, PgpGeneralException, PGPException, SignatureException {
        PgpDecryptVerifyResult returnData = new PgpDecryptVerifyResult();

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        int currentProgress = 0;
        updateProgress(R.string.progress_reading_data, currentProgress, 100);

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new PgpGeneralException(mContext.getString(R.string.error_invalid_data));
        }

        InputStream clear;
        PGPEncryptedData encryptedData;

        currentProgress += 5;

        // TODO: currently we always only look at the first known key or symmetric encryption,
        // there might be more...
        if (mAssumeSymmetric) {
            PGPPBEEncryptedData pbe = null;
            Iterator<?> it = enc.getEncryptedDataObjects();
            // find secret key
            while (it.hasNext()) {
                Object obj = it.next();
                if (obj instanceof PGPPBEEncryptedData) {
                    pbe = (PGPPBEEncryptedData) obj;
                    break;
                }
            }

            if (pbe == null) {
                throw new PgpGeneralException(
                        mContext.getString(R.string.error_no_symmetric_encryption_packet));
            }

            updateProgress(R.string.progress_preparing_streams, currentProgress, 100);

            PGPDigestCalculatorProvider digestCalcProvider = new JcaPGPDigestCalculatorProviderBuilder()
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build();
            PBEDataDecryptorFactory decryptorFactory = new JcePBEDataDecryptorFactoryBuilder(
                    digestCalcProvider).setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(
                    mPassphrase.toCharArray());

            clear = pbe.getDataStream(decryptorFactory);

            encryptedData = pbe;
            currentProgress += 5;
        } else {
            updateProgress(R.string.progress_finding_key, currentProgress, 100);

            PGPPublicKeyEncryptedData pbe = null;
            Key secretKey = null;
            Iterator<?> it = enc.getEncryptedDataObjects();
            // find secret key
            while (it.hasNext()) {
                Object obj = it.next();
                if (obj instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) obj;
                    secretKey = mKeyProvider.getSecretKeyByKeyId(encData.getKeyID());
                    if (secretKey != null) {
                        // secret key exists in database

                        // allow only a specific key for decryption?
                        if (mEnforcedKeyId != 0) {
                            // TODO: improve this code! get master key directly!
                            KeyRing secretKeyRing =
                                mKeyProvider.getSecretKeyRingByKeyId(encData.getKeyID());
                            long masterKeyId = secretKeyRing.getMasterKey().getKeyId();
                            Log.d(Constants.TAG, "encData.getKeyID():" + encData.getKeyID());
                            Log.d(Constants.TAG, "mEnforcedKeyId: " + mEnforcedKeyId);
                            Log.d(Constants.TAG, "masterKeyId: " + masterKeyId);

                            if (mEnforcedKeyId != masterKeyId) {
                                throw new PgpGeneralException(
                                    mContext.getString(R.string.error_no_secret_key_found));
                            }
                        }

                        pbe = encData;

                        // if no passphrase was explicitly set try to get it from the cache service
                        if (mPassphrase == null) {
                            // returns "" if key has no passphrase
                            mPassphrase = PassphraseCacheService.getCachedPassphrase(
                                                mContext, encData.getKeyID());

                            // if passphrase was not cached, return here indicating that a
                            // passphrase is missing!
                            if (mPassphrase == null) {
                                returnData.setKeyPassphraseNeeded(true);
                                return returnData;
                            }
                        }

                        break;
                    }


                }
            }

            if (secretKey == null) {
                throw new PgpGeneralException(mContext.getString(R.string.error_no_secret_key_found));
            }

            currentProgress += 5;
            updateProgress(R.string.progress_extracting_key, currentProgress, 100);
            PGPPrivateKey privateKey;
            try {
                PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(
                                mPassphrase.toCharArray());
                privateKey = secretKey.extractPrivateKey(keyDecryptor);
            } catch (PGPException e) {
                throw new PGPException(mContext.getString(R.string.error_wrong_passphrase));
            }
            if (privateKey == null) {
                throw new PgpGeneralException(
                        mContext.getString(R.string.error_could_not_extract_private_key));
            }
            currentProgress += 5;
            updateProgress(R.string.progress_preparing_streams, currentProgress, 100);

            PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(privateKey);

            clear = pbe.getDataStream(decryptorFactory);

            encryptedData = pbe;
            currentProgress += 5;
        }

        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
        Object dataChunk = plainFact.nextObject();
        PGPOnePassSignature signature = null;
        OpenPgpSignatureResult signatureResult = null;
        Key signatureKey = null;
        int signatureIndex = -1;

        if (dataChunk instanceof PGPCompressedData) {
            updateProgress(R.string.progress_decompressing_data, currentProgress, 100);

            PGPObjectFactory fact = new PGPObjectFactory(
                    ((PGPCompressedData) dataChunk).getDataStream());
            dataChunk = fact.nextObject();
            plainFact = fact;
            currentProgress += 10;
        }

        long signatureKeyId = 0;
        if (dataChunk instanceof PGPOnePassSignatureList) {
            updateProgress(R.string.progress_processing_signature, currentProgress, 100);

            signatureResult = new OpenPgpSignatureResult();
            PGPOnePassSignatureList sigList = (PGPOnePassSignatureList) dataChunk;
            for (int i = 0; i < sigList.size(); ++i) {
                signature = sigList.get(i);
                signatureKey = mKeyProvider.getPublicKeyByKeyId(signature.getKeyID());
                if (signatureKeyId == 0) {
                    signatureKeyId = signature.getKeyID();
                }
                if (signatureKey == null) {
                    signature = null;
                } else {
                    signatureIndex = i;
                    signatureKeyId = signature.getKeyID();
                    String userId = null;
                    KeyRing signKeyRing = mKeyProvider.getPublicKeyRingByKeyId(signatureKeyId);
                    if (signKeyRing != null) {
                        userId = signKeyRing.getMasterKey().getMainUserId();
                    }
                    signatureResult.setUserId(userId);
                    break;
                }
            }

            signatureResult.setKeyId(signatureKeyId);

            if (signature != null) {
                JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
                    new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);

                signature.init(contentVerifierBuilderProvider, signatureKey.getPublicKey());
            } else {
                signatureResult.setStatus(OpenPgpSignatureResult.SIGNATURE_UNKNOWN_PUB_KEY);
            }

            dataChunk = plainFact.nextObject();
            currentProgress += 10;
        }

        if (dataChunk instanceof PGPSignatureList) {
            dataChunk = plainFact.nextObject();
        }

        if (dataChunk instanceof PGPLiteralData) {
            updateProgress(R.string.progress_decrypting, currentProgress, 100);

            PGPLiteralData literalData = (PGPLiteralData) dataChunk;

            byte[] buffer = new byte[1 << 16];
            InputStream dataIn = literalData.getInputStream();

            int startProgress = currentProgress;
            int endProgress = 100;
            if (signature != null) {
                endProgress = 90;
            } else if (encryptedData.isIntegrityProtected()) {
                endProgress = 95;
            }

            int n;
            // TODO: progress calculation is broken here! Try to rework it based on commented code!
//            int progress = 0;
            long startPos = mData.getStreamPosition();
            while ((n = dataIn.read(buffer)) > 0) {
                mOutputStream.write(buffer, 0, n);
//                progress += n;
                if (signature != null) {
                    try {
                        signature.update(buffer, 0, n);
                    } catch (SignatureException e) {
                        signatureResult.setStatus(OpenPgpSignatureResult.SIGNATURE_ERROR);
                        signature = null;
                    }
                }
                // TODO: dead code?!
                // unknown size, but try to at least have a moving, slowing down progress bar
//                currentProgress = startProgress + (endProgress - startProgress) * progress
//                        / (progress + 100000);
                if (mData.getSize() - startPos == 0) {
                    currentProgress = endProgress;
                } else {
                    currentProgress = (int) (startProgress + (endProgress - startProgress)
                            * (mData.getStreamPosition() - startPos) / (mData.getSize() - startPos));
                }
                updateProgress(currentProgress, 100);
            }

            if (signature != null) {
                updateProgress(R.string.progress_verifying_signature, 90, 100);

                PGPSignatureList signatureList = (PGPSignatureList) plainFact.nextObject();
                PGPSignature messageSignature = signatureList.get(signatureIndex);

                // these are not cleartext signatures!
                // TODO: what about binary signatures?
                signatureResult.setSignatureOnly(false);

                //Now check binding signatures
                boolean validKeyBinding =
                    verifyKeyBinding(messageSignature, signatureKey.getPublicKey());
                boolean validSignature = signature.verify(messageSignature);

                // TODO: implement CERTIFIED!
                if (validKeyBinding & validSignature) {
                    signatureResult.setStatus(OpenPgpSignatureResult.SIGNATURE_SUCCESS_UNCERTIFIED);
                }
            }
        }

        if (encryptedData.isIntegrityProtected()) {
            updateProgress(R.string.progress_verifying_integrity, 95, 100);

            if (encryptedData.verify()) {
                // passed
                Log.d(Constants.TAG, "Integrity verification: success!");
            } else {
                // failed
                Log.d(Constants.TAG, "Integrity verification: failed!");
                throw new PgpGeneralException(mContext.getString(R.string.error_integrity_check_failed));
            }
        } else {
            // no integrity check
            Log.e(Constants.TAG, "Encrypted mData was not integrity protected!");
            // TODO: inform user?
        }

        updateProgress(R.string.progress_done, 100, 100);

        returnData.setSignatureResult(signatureResult);
        return returnData;
    }

    /**
     * This method verifies cleartext signatures
     * as defined in http://tools.ietf.org/html/rfc4880#section-7
     * <p/>
     * The method is heavily based on
     * pg/src/main/java/org/spongycastle/openpgp/examples/ClearSignedFileProcessor.java
     *
     * @return
     * @throws IOException
     * @throws PgpGeneralException
     * @throws PGPException
     * @throws SignatureException
     */
    private PgpDecryptVerifyResult verifyCleartextSignature(ArmoredInputStream aIn)
            throws IOException, PgpGeneralException, PGPException, SignatureException {
        PgpDecryptVerifyResult returnData = new PgpDecryptVerifyResult();
        OpenPgpSignatureResult signatureResult = new OpenPgpSignatureResult();
        // cleartext signatures are never encrypted ;)
        signatureResult.setSignatureOnly(true);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        updateProgress(R.string.progress_done, 0, 100);

        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, aIn);
        byte[] lineSep = getLineSeparator();

        byte[] line = lineOut.toByteArray();
        out.write(line, 0, getLengthWithoutSeparator(line));
        out.write(lineSep);

        while (lookAhead != -1 && aIn.isClearText()) {
            lookAhead = readInputLine(lineOut, lookAhead, aIn);
            line = lineOut.toByteArray();
            out.write(line, 0, getLengthWithoutSeparator(line));
            out.write(lineSep);
        }

        out.close();

        byte[] clearText = out.toByteArray();
        mOutputStream.write(clearText);

        updateProgress(R.string.progress_processing_signature, 60, 100);
        PGPObjectFactory pgpFact = new PGPObjectFactory(aIn);

        PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
        if (sigList == null) {
            throw new PgpGeneralException(mContext.getString(R.string.error_corrupt_data));
        }
        PGPSignature signature = null;
        long signatureKeyId = 0;
        Key signatureKey = null;
        for (int i = 0; i < sigList.size(); ++i) {
            signature = sigList.get(i);
            signatureKey = mKeyProvider.getPublicKeyByKeyId(signature.getKeyID());
            if (signatureKeyId == 0) {
                signatureKeyId = signature.getKeyID();
            }

            if (signatureKey == null) {
                signature = null;
            } else {
                signatureKeyId = signature.getKeyID();
                String userId = null;
                KeyRing signKeyRing = mKeyProvider.getPublicKeyRingByKeyId(signatureKeyId);
                if (signKeyRing != null) {
                    userId = signKeyRing.getMasterKey().getMainUserId();
                }
                signatureResult.setUserId(userId);
                break;
            }
        }

        signatureResult.setKeyId(signatureKeyId);

        if (signature == null) {
            signatureResult.setStatus(OpenPgpSignatureResult.SIGNATURE_UNKNOWN_PUB_KEY);
            returnData.setSignatureResult(signatureResult);

            updateProgress(R.string.progress_done, 100, 100);
            return returnData;
        }

        JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);

        signature.init(contentVerifierBuilderProvider, signatureKey.getPublicKey());

        InputStream sigIn = new BufferedInputStream(new ByteArrayInputStream(clearText));

        lookAhead = readInputLine(lineOut, sigIn);

        processLine(signature, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                signature.update((byte) '\r');
                signature.update((byte) '\n');

                processLine(signature, lineOut.toByteArray());
            } while (lookAhead != -1);
        }

        //Now check binding signatures
        boolean validKeyBinding = verifyKeyBinding(signature, signatureKey.getPublicKey());
        boolean validSignature = signature.verify();

        if (validSignature & validKeyBinding) {
            signatureResult.setStatus(OpenPgpSignatureResult.SIGNATURE_SUCCESS_UNCERTIFIED);
        }

        // TODO: what about SIGNATURE_SUCCESS_CERTIFIED and SIGNATURE_ERROR????

        returnData.setSignatureResult(signatureResult);

        updateProgress(R.string.progress_done, 100, 100);
        return returnData;
    }

    private boolean verifyKeyBinding(PGPSignature signature, PGPPublicKey signatureKey) {
        long signatureKeyId = signature.getKeyID();
        boolean validKeyBinding = false;

        KeyRing signKeyRing = mKeyProvider.getPublicKeyRingByKeyId(signatureKeyId);
        Key mKey = null;
        if (signKeyRing != null) {
            mKey = signKeyRing.getMasterKey();
        }

        if (signature.getKeyID() != mKey.getKeyId()) {
            validKeyBinding = verifyKeyBinding(mKey.getPublicKey(), signatureKey);
        } else {
            // if the key used to make the signature was the master key, no need to check binding sigs
            validKeyBinding = true;
        }
        return validKeyBinding;
    }

    private boolean verifyKeyBinding(PGPPublicKey masterPublicKey, PGPPublicKey signingPublicKey) {
        boolean validSubkeyBinding = false;
        boolean validTempSubkeyBinding = false;
        boolean validPrimaryKeyBinding = false;

        JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);

        Iterator<PGPSignature> itr = signingPublicKey.getSignatures();

        while (itr.hasNext()) {
            // what does gpg do if the subkey binding is wrong?
            // gpg has an invalid subkey binding error on key import I think, but doesn't shout
            // about keys without subkey signing. Can't get it to import a slightly broken one
            // either, so we will err on bad subkey binding here.
            PGPSignature sig = itr.next();
            if (sig.getKeyID() == masterPublicKey.getKeyID() &&
                sig.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                // check and if ok, check primary key binding.
                try {
                    sig.init(contentVerifierBuilderProvider, masterPublicKey);
                    validTempSubkeyBinding = sig.verifyCertification(masterPublicKey, signingPublicKey);
                } catch (PGPException e) {
                    continue;
                } catch (SignatureException e) {
                    continue;
                }

                if (validTempSubkeyBinding) {
                    validSubkeyBinding = true;
                }

                if (validTempSubkeyBinding) {
                    validPrimaryKeyBinding =
                        verifyPrimaryKeyBinding(sig.getUnhashedSubPackets(), masterPublicKey,
                                                signingPublicKey);

                    if (validPrimaryKeyBinding) {
                        break;
                    }

                    validPrimaryKeyBinding =
                        verifyPrimaryKeyBinding(sig.getHashedSubPackets(), masterPublicKey,
                                                signingPublicKey);
                    if (validPrimaryKeyBinding) {
                        break;
                    }
                }
            }
        }
        return (validSubkeyBinding & validPrimaryKeyBinding);
    }

    private static boolean verifyPrimaryKeyBinding(PGPSignatureSubpacketVector packets,
                                                   PGPPublicKey masterPublicKey,
                                                   PGPPublicKey signingPublicKey) {
        boolean validPrimaryKeyBinding = false;
        JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        PGPSignatureList eSigList;

        if (packets.hasSubpacket(SignatureSubpacketTags.EMBEDDED_SIGNATURE)) {
            try {
                eSigList = packets.getEmbeddedSignatures();
            } catch (IOException e) {
                return false;
            } catch (PGPException e) {
                return false;
            }
            for (int j = 0; j < eSigList.size(); ++j) {
                PGPSignature emSig = eSigList.get(j);
                if (emSig.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING) {
                    try {
                        emSig.init(contentVerifierBuilderProvider, signingPublicKey);
                        validPrimaryKeyBinding =
                            emSig.verifyCertification(masterPublicKey, signingPublicKey);
                        if (validPrimaryKeyBinding) {
                            break;
                        }
                    } catch (PGPException e) {
                        continue;
                    } catch (SignatureException e) {
                        continue;
                    }
                }
            }
        }

        return validPrimaryKeyBinding;
    }

    /**
     * Mostly taken from ClearSignedFileProcessor in Bouncy Castle
     *
     * @param sig
     * @param line
     * @throws SignatureException
     * @throws IOException
     */
    private static void processLine(PGPSignature sig, byte[] line)
            throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
            throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
            throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        } while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
            throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    private static int getLengthWithoutSeparator(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isLineEnding(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return b == '\r' || b == '\n' || b == '\t' || b == ' ';
    }

    private static byte[] getLineSeparator() {
        String nl = System.getProperty("line.separator");
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }
}
