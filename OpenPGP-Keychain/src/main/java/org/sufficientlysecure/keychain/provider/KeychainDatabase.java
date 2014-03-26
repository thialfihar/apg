/*
 * Copyright (C) 2012-2013 Dominik Schürmann <dominik@dominikschuermann.de>
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

package org.thialfihar.android.apg.provider;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.provider.BaseColumns;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.util.Log;

public class KeychainDatabase extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "apg";
    private static final int DATABASE_VERSION = 3;

    public interface Tables {
        String KEY_RINGS = "key_rings";
        String KEYS = "keys";
        String USER_IDS = "user_ids";
        String API_APPS = "api_apps";
        String API_ACCOUNTS = "api_accounts";
    }

    private static final String CREATE_KEY_RINGS = "CREATE TABLE IF NOT EXISTS " + Tables.KEY_RINGS
            + " (" + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + KeyRingsColumns.MASTER_KEY_ID + " INT64, "
            + KeyRingsColumns.TYPE + " INTEGER, "
            + KeyRingsColumns.KEY_RING_DATA + " BLOB)";

    private static final String CREATE_KEYS = "CREATE TABLE IF NOT EXISTS " + Tables.KEYS + " ("
            + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + KeysColumns.KEY_ID + " INT64, "
            + KeysColumns.TYPE + " INTEGER, "
            + KeysColumns.IS_MASTER_KEY + " INTEGER, "
            + KeysColumns.ALGORITHM + " INTEGER, "
            + KeysColumns.KEY_SIZE + " INTEGER, "
            + KeysColumns.CAN_CERTIFY + " INTEGER, "
            + KeysColumns.CAN_SIGN + " INTEGER, "
            + KeysColumns.CAN_ENCRYPT + " INTEGER, "
            + KeysColumns.IS_REVOKED + " INTEGER, "
            + KeysColumns.CREATION + " INTEGER, "
            + KeysColumns.EXPIRY + " INTEGER, "
            + KeysColumns.KEY_DATA + " BLOB,"
            + KeysColumns.RANK + " INTEGER, "
            + KeysColumns.FINGERPRINT + " BLOB, "
            + KeysColumns.KEY_RING_ROW_ID + " INTEGER NOT NULL, "
            + "FOREIGN KEY(" + KeysColumns.KEY_RING_ROW_ID + ") REFERENCES "
            + Tables.KEY_RINGS + "(" + BaseColumns._ID + ") ON DELETE CASCADE)";

    private static final String CREATE_USER_IDS = "CREATE TABLE IF NOT EXISTS " + Tables.USER_IDS
            + " (" + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + UserIdsColumns.USER_ID + " TEXT, "
            + UserIdsColumns.RANK + " INTEGER, "
            + UserIdsColumns.KEY_RING_ROW_ID + " INTEGER NOT NULL, "
            + "FOREIGN KEY(" + UserIdsColumns.KEY_RING_ROW_ID + ") REFERENCES "
            + Tables.KEY_RINGS + "(" + BaseColumns._ID + ") ON DELETE CASCADE)";

    private static final String CREATE_API_APPS = "CREATE TABLE IF NOT EXISTS " + Tables.API_APPS
            + " (" + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + ApiAppsColumns.PACKAGE_NAME + " TEXT NOT NULL UNIQUE, "
            + ApiAppsColumns.PACKAGE_SIGNATURE + " BLOB)";

    private static final String CREATE_API_APPS_ACCOUNTS = "CREATE TABLE IF NOT EXISTS " + Tables.API_ACCOUNTS
            + " (" + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + ApiAppsAccountsColumns.ACCOUNT_NAME + " TEXT NOT NULL, "
            + ApiAppsAccountsColumns.KEY_ID + " INT64, "
            + ApiAppsAccountsColumns.ENCRYPTION_ALGORITHM + " INTEGER, "
            + ApiAppsAccountsColumns.HASH_ALORITHM + " INTEGER, "
            + ApiAppsAccountsColumns.COMPRESSION + " INTEGER, "
            + ApiAppsAccountsColumns.PACKAGE_NAME + " TEXT NOT NULL, "
            + "UNIQUE(" + ApiAppsAccountsColumns.ACCOUNT_NAME + ", "
            + ApiAppsAccountsColumns.PACKAGE_NAME + "), "
            + "FOREIGN KEY(" + ApiAppsAccountsColumns.PACKAGE_NAME + ") REFERENCES "
            + Tables.API_APPS + "(" + ApiAppsColumns.PACKAGE_NAME + ") ON DELETE CASCADE)";

    KeychainDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.w(Constants.TAG, "Creating database...");

        db.execSQL("CREATE TABLE key_rings(" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "master_key_id INT64, " +
            "type INTEGER, " +
            "key_ring_data BLOB)");

        db.execSQL("CREATE TABLE keys(" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "key_ring_row_id INTEGER NOT NULL, " +
            "key_id INT64, " +
            "type INTEGER, " +
            "is_master_key INTEGER, " +
            "algorithm INTEGER, " +
            "key_size INTEGER, " +
            "can_certify INTEGER, " +
            "can_sign INTEGER, " +
            "can_encrypt INTEGER, " +
            "is_revoked INTEGER, " +
            "creation INTEGER, " +
            "expiry INTEGER, " +
            "rank INTEGER, " +
            "key_data BLOB," +
            "fingerprint BLOB, " +
            "FOREIGN KEY(key_ring_row_id) REFERENCES key_rings(_id) ON DELETE CASCADE)");

        db.execSQL("CREATE TABLE user_ids(" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "key_ring_row_id INTEGER NOT NULL, " +
            "user_id TEXT, " +
            "rank INTEGER, " +
            "FOREIGN KEY(key_ring_row_id) REFERENCES key_rings(_id) ON DELETE CASCADE)");

        db.execSQL("CREATE TABLE api_apps(" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "package_name TEXT UNIQUE, " +
            "package_signature BLOB, " +
            "key_id INT64, " +
            "encryption_algorithm INTEGER, " +
            "hash_algorithm INTEGER, " +
            "compression INTEGER)");

        db.execSQL(CREATE_API_APPS_ACCOUNTS);
    }

    @Override
    public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
        if (!db.isReadOnly()) {
            // Enable foreign key constraints
            db.execSQL("PRAGMA foreign_keys=ON;");
        }
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.w(Constants.TAG, "Upgrading database from version " + oldVersion + " to " + newVersion);

        // Upgrade from oldVersion through all cases to newest one
        for (int version = oldVersion; version < newVersion; ++version) {
            Log.w(Constants.TAG, "Upgrading database to version " + (version + 1));

            switch (version) {
                case 2:
                    db.beginTransaction();
                    try {
                        // accounts aren't used anymore
                        db.execSQL("DROP TABLE accounts");

                        // rename old databases
                        db.execSQL("ALTER TABLE key_rings RENAME TO orig_key_rings");
                        db.execSQL("ALTER TABLE keys RENAME TO orig_keys");
                        db.execSQL("ALTER TABLE user_ids RENAME TO orig_user_ids");

                        db.execSQL("CREATE TABLE key_rings(" +
                            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            "master_key_id INT64, " +
                            "type INTEGER, " +
                            "key_ring_data BLOB)");

                        db.execSQL("CREATE TABLE keys(" +
                            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            "key_ring_row_id INTEGER NOT NULL, " +
                            "key_id INT64, " +
                            "type INTEGER, " +
                            "is_master_key INTEGER, " +
                            "algorithm INTEGER, " +
                            "key_size INTEGER, " +
                            "can_certify INTEGER, " +
                            "can_sign INTEGER, " +
                            "can_encrypt INTEGER, " +
                            "is_revoked INTEGER, " +
                            "creation INTEGER, " +
                            "expiry INTEGER, " +
                            "rank INTEGER, " +
                            "key_data BLOB," +
                            "fingerprint BLOB, " +
                            "FOREIGN KEY(key_ring_row_id) REFERENCES key_rings(_id) ON DELETE CASCADE)");

                        db.execSQL("CREATE TABLE user_ids(" +
                            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            "key_ring_row_id INTEGER NOT NULL, " +
                            "user_id TEXT, " +
                            "rank INTEGER, " +
                            "FOREIGN KEY(key_ring_row_id) REFERENCES key_rings(_id) ON DELETE CASCADE)");

                        db.execSQL("CREATE TABLE api_apps(" +
                            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            "package_name TEXT UNIQUE, " +
                            "package_signature BLOB, " +
                            "key_id INT64, " +
                            "encryption_algorithm INTEGER, " +
                            "hash_algorithm INTEGER, " +
                            "compression INTEGER)");

                        // copy data
                        db.execSQL("INSERT INTO key_rings(_id, master_key_id, type, key_ring_data) " +
                                   "SELECT _id, c_master_key_id, c_type, c_key_ring_data " +
                                   "FROM orig_key_rings");

                        db.execSQL("INSERT INTO keys(_id, key_ring_row_id, key_id, type, is_master_key, " +
                                    "algorithm, key_size, can_certify, can_sign, can_encrypt, " +
                                    "is_revoked, creation, expiry, rank, key_data, " +
                                    "fingerprint) " +
                                   "SELECT _id, c_key_ring_id, c_key_id, c_type, c_is_master_key, " +
                                    "c_algorithm, c_key_size, c_is_master_key, c_can_sign, c_can_encrypt, " +
                                    "0, c_creation, c_expiry, 0, c_key_data, null " +
                                   "FROM orig_keys");

                        db.execSQL("INSERT INTO user_ids(_id, key_ring_row_id, user_id, rank) " +
                                   "SELECT orig_user_ids._id, orig_keys.c_key_ring_id, c_user_id, " +
                                        "orig_user_ids.c_rank " +
                                   "FROM orig_user_ids JOIN orig_keys ON " +
                                        "orig_keys._id = orig_user_ids.c_key_id");

                        db.execSQL("UPDATE keys SET " +
                                    "rank = (SELECT COUNT(1) FROM keys AS keys2 " +
                                        "WHERE keys2.key_ring_row_id = keys.key_ring_row_id AND " +
                                            "keys2._id < keys._id)");

                        db.execSQL("UPDATE user_ids SET " +
                                    "rank = (SELECT COUNT(1) FROM user_ids AS user_ids2 " +
                                        "WHERE user_ids2.key_ring_row_id = user_ids.key_ring_row_id AND " +
                                            "user_ids2._id < user_ids._id)");

                        db.setTransactionSuccessful();
                    } finally {
                        db.endTransaction();
                    }
                    break;
                case 7:
                    // new db layout for api apps
                    db.execSQL("DROP TABLE IF EXISTS " + Tables.API_APPS);
                    db.execSQL(CREATE_API_APPS);
                    db.execSQL(CREATE_API_APPS_ACCOUNTS);
                    break;
                default:
                    break;

            }
        }
    }

}
