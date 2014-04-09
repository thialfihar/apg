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

package org.sufficientlysecure.keychain.provider;

import android.net.Uri;
import android.provider.BaseColumns;
import org.sufficientlysecure.keychain.Constants;

public class KeychainContract {

    interface KeyRingsColumns {
        String MASTER_KEY_ID = "master_key_id"; // not a database id
        String TYPE = "type"; // see KeyTypes
        String KEY_RING_DATA = "key_ring_data"; // PGPPublicKeyRing / PGPSecretKeyRing blob
    }

    interface KeysColumns {
        String KEY_ID = "key_id"; // not a database id
        String TYPE = "type"; // see KeyTypes
        String IS_MASTER_KEY = "is_master_key";
        String ALGORITHM = "algorithm";
        String KEY_SIZE = "key_size";
        String CAN_CERTIFY = "can_certify";
        String CAN_SIGN = "can_sign";
        String CAN_ENCRYPT = "can_encrypt";
        String IS_REVOKED = "is_revoked";
        String CREATION = "creation";
        String EXPIRY = "expiry";
        String KEY_RING_ROW_ID = "key_ring_row_id"; // foreign key to key_rings._ID
        String KEY_DATA = "key_data"; // PGPPublicKey/PGPSecretKey blob
        String RANK = "rank";
        String FINGERPRINT = "fingerprint";
    }

    interface UserIdsColumns {
        String KEY_RING_ROW_ID = "key_ring_row_id"; // foreign key to key_rings._ID
        String USER_ID = "user_id"; // not a database id
        String RANK = "rank"; // ONLY used for sorting! no key, no nothing!
        String IS_PRIMARY = "is_primary";
        String IS_REVOKED = "is_revoked";
    }

    interface CertsColumns {
        String MASTER_KEY_ID = "master_key_id";
        String RANK = "rank";
        String KEY_ID_CERTIFIER = "key_id_certifier";
        String TYPE = "type";
        String VERIFIED = "verified";
        String CREATION = "creation";
        String DATA = "data";
    }

    interface ApiAppsColumns {
        String PACKAGE_NAME = "package_name";
        String PACKAGE_SIGNATURE = "package_signature";
        String KEY_ID = "key_id"; // not a database id
        String ENCRYPTION_ALGORITHM = "encryption_algorithm";
        String HASH_ALORITHM = "hash_algorithm";
        String COMPRESSION = "compression";
    }

    public static final class KeyTypes {
        public static final int PUBLIC = 0;
        public static final int SECRET = 1;
    }

    public static final String CONTENT_AUTHORITY = Constants.PACKAGE_NAME + ".provider";

    private static final Uri BASE_CONTENT_URI_INTERNAL = Uri
            .parse("content://" + CONTENT_AUTHORITY);

    public static final String BASE_KEY_RINGS = "key_rings";
    public static final String BASE_DATA = "data";

    public static final String PATH_PUBLIC = "public";
    public static final String PATH_SECRET = "secret";

    public static final String PATH_FIND = "find";
    public static final String PATH_BY_EMAIL = "email";
    public static final String PATH_BY_SUBKEY = "subkey";

    public static final String PATH_USER_IDS = "user_ids";
    public static final String PATH_KEYS = "keys";

    public static final String BASE_API_APPS = "api_apps";
    public static final String PATH_BY_PACKAGE_NAME = "package_name";

    public static final String BASE_CERTS = "certs";

    public static class KeyRings implements BaseColumns, KeysColumns, UserIdsColumns {
        public static final String MASTER_KEY_ID = KeysColumns.MASTER_KEY_ID;
        public static final String IS_REVOKED = KeysColumns.IS_REVOKED;
        public static final String VERIFIED = CertsColumns.VERIFIED;
        public static final String HAS_SECRET = "has_secret";

        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_KEY_RINGS).build();

        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.sufficientlysecure.openkeychain.key_ring";
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.sufficientlysecure.openkeychain.key_ring";

        public static Uri buildUnifiedKeyRingsUri() {
            return CONTENT_URI;
        }

        public static Uri buildPublicKeyRingsUri() {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).build();
        }

        public static Uri buildPublicKeyRingsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId).build();
        }

        public static Uri buildPublicKeyRingsByMasterKeyIdUri(String masterKeyId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC)
                    .appendPath(PATH_BY_MASTER_KEY_ID).appendPath(masterKeyId).build();
        }

        public static Uri buildPublicKeyRingsByEmailsUri(String emails) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(PATH_BY_EMAILS)
                    .appendPath(emails).build();
        }
        public static Uri buildUnifiedKeyRingUri(String masterKeyId) {
            return CONTENT_URI.buildUpon().appendPath(masterKeyId).appendPath(PATH_UNIFIED).build();
        }
        public static Uri buildUnifiedKeyRingUri(Uri uri) {
            return CONTENT_URI.buildUpon().appendPath(uri.getPathSegments().get(1)).appendPath(PATH_UNIFIED).build();
        }

        public static Uri buildUnifiedKeyRingsFindByEmailUri(String email) {
            return CONTENT_URI.buildUpon().appendPath(PATH_FIND).appendPath(PATH_BY_EMAIL).appendPath(email).build();
        }
        public static Uri buildUnifiedKeyRingsFindBySubkeyUri(String subkey) {
            return CONTENT_URI.buildUpon().appendPath(PATH_FIND).appendPath(PATH_BY_SUBKEY).appendPath(subkey).build();
        }

    }

    public static class KeyRingData implements KeyRingsColumns, BaseColumns {
        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_KEY_RINGS).build();

        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.sufficientlysecure.openkeychain.key_ring_data";
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.sufficientlysecure.openkeychain.key_ring_data";

        public static Uri buildPublicKeyRingUri() {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).build();
        }
        public static Uri buildPublicKeyRingUri(String masterKeyId) {
            return CONTENT_URI.buildUpon().appendPath(masterKeyId).appendPath(PATH_PUBLIC).build();
        }

        public static Uri buildSecretKeyRingsUri() {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).build();
        }

        public static Uri buildSecretKeyRingsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId).build();
        }

        public static Uri buildSecretKeyRingsByMasterKeyIdUri(String masterKeyId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET)
                    .appendPath(PATH_BY_MASTER_KEY_ID).appendPath(masterKeyId).build();
        }

    }

    public static class Keys implements KeysColumns, BaseColumns {
        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_KEY_RINGS).build();

        /**
         * Use if multiple items get returned
         */
        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.thialfihar.apg.key";

        /**
         * Use if a single item is returned
         */
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.thialfihar.apg.key";

        public static Uri buildPublicKeysUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).build();
        }

        public static Uri buildPublicKeysUri(String keyRingRowId, String keyRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).appendPath(keyRowId).build();
        }

        public static Uri buildSecretKeysUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).build();
        }

        public static Uri buildSecretKeysUri(String keyRingRowId, String keyRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).appendPath(keyRowId).build();
        }

        public static Uri buildKeysUri(Uri keyRingUri) {
            return keyRingUri.buildUpon().appendPath(PATH_KEYS).build();
        }

        public static Uri buildKeysUri(Uri keyRingUri, String keyRowId) {
            return keyRingUri.buildUpon().appendPath(PATH_KEYS).appendPath(keyRowId).build();
        }
    }

    public static class UserIds implements UserIdsColumns, BaseColumns {
        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_KEY_RINGS).build();

        /**
         * Use if multiple items get returned
         */
        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.thialfihar.apg.user_id";

        /**
         * Use if a single item is returned
         */
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.thialfihar.apg.user_id";

        public static Uri buildPublicUserIdsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).build();
        }

        public static Uri buildPublicUserIdsUri(String keyRingRowId, String userIdRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).appendPath(userIdRowId).build();
        }

        public static Uri buildSecretUserIdsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).build();
        }

        public static Uri buildSecretUserIdsUri(String keyRingRowId, String userIdRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).appendPath(userIdRowId).build();
        }

        public static Uri buildUserIdsUri(Uri keyRingUri) {
            return keyRingUri.buildUpon().appendPath(PATH_USER_IDS).build();
        }

        public static Uri buildUserIdsUri(Uri keyRingUri, String userIdRowId) {
            return keyRingUri.buildUpon().appendPath(PATH_USER_IDS).appendPath(userIdRowId).build();
        }
    }

    public static class ApiApps implements ApiAppsColumns, BaseColumns {
        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_API_APPS).build();

        /**
         * Use if multiple items get returned
         */
        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.thialfihar.apg.api_apps";

        /**
         * Use if a single item is returned
         */
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.thialfihar.apg.api_apps";

        public static Uri buildIdUri(String rowId) {
            return CONTENT_URI.buildUpon().appendPath(rowId).build();
        }

        public static Uri buildByPackageNameUri(String packageName) {
            return CONTENT_URI.buildUpon().appendPath(PATH_BY_PACKAGE_NAME).appendPath(packageName)
                    .build();
        }
    }

    public static class Certs implements CertsColumns, BaseColumns {
        public static final String USER_ID = UserIdsColumns.USER_ID;
        public static final String SIGNER_UID = "signer_user_id";

        public static final int VERIFIED_SECRET = 1;
        public static final int VERIFIED_SELF = 2;

        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_CERTS).build();

        // do we even need this one...? just using it as default for database insert notifications~
        public static Uri buildCertsUri(String rowId) {
            return CONTENT_URI.buildUpon().appendPath(rowId).build();
        }
        public static Uri buildCertsSpecificUri(String masterKeyId, String rank, String certifier) {
            return CONTENT_URI.buildUpon().appendPath(masterKeyId).appendPath(PATH_CERTS).appendPath(rank).appendPath(certifier).build();
        }
        public static Uri buildCertsUri(Uri uri) {
            return CONTENT_URI.buildUpon().appendPath(uri.getPathSegments().get(1)).appendPath(PATH_CERTS).build();
        }

    }

    public static class DataStream {
        public static final Uri CONTENT_URI = BASE_CONTENT_URI_INTERNAL.buildUpon()
                .appendPath(BASE_DATA).build();

        public static Uri buildDataStreamUri(String streamFilename) {
            return CONTENT_URI.buildUpon().appendPath(streamFilename).build();
        }
    }

    private KeychainContract() {
    }
}
