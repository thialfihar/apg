/*
 * Copyright (C) 2012-2014 Dominik Schürmann <dominik@dominikschuermann.de>
 * Copyright (C) 2014 Vincent Breitmoser <v.breitmoser@mugenguild.com>
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
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.provider.BaseColumns;

import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.provider.KeychainContract.ApiAppsAccountsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.ApiAppsAllowedKeysColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.ApiAppsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.CertsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.KeyRingsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.KeysColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.UserPacketsColumns;
import org.sufficientlysecure.keychain.ui.ConsolidateDialogActivity;
import org.sufficientlysecure.keychain.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * SQLite Datatypes (from http://www.sqlite.org/datatype3.html)
 * - NULL. The value is a NULL value.
 * - INTEGER. The value is a signed integer, stored in 1, 2, 3, 4, 6, or 8 bytes depending on the magnitude of the value.
 * - REAL. The value is a floating point value, stored as an 8-byte IEEE floating point number.
 * - TEXT. The value is a text string, stored using the database encoding (UTF-8, UTF-16BE or UTF-16LE).
 * - BLOB. The value is a blob of data, stored exactly as it was input.
 */
public class KeychainDatabase extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "apg";
    private static final int DATABASE_VERSION = 4;
    private Context mContext;

    public interface Tables {
        String KEY_RINGS_PUBLIC = "keyrings_public";
        String KEY_RINGS_SECRET = "keyrings_secret";
        String KEYS = "keys";
        String USER_PACKETS = "user_packets";
        String CERTS = "certs";
        String API_APPS = "api_apps";
        String API_ACCOUNTS = "api_accounts";
        String API_ALLOWED_KEYS = "api_allowed_keys";
    }

    public KeychainDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        mContext = context;
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.w(Constants.TAG, "Creating database...");

        db.execSQL("CREATE TABLE IF NOT EXISTS keyrings_public ("
            + "master_key_id INTEGER PRIMARY KEY,"
            + "key_ring_data BLOB "
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS keyrings_secret ("
            + "master_key_id INTEGER PRIMARY KEY,"
            + "key_ring_data BLOB, "
            + "FOREIGN KEY(master_key_id) "
                + "REFERENCES keyrings_public(master_key_id) ON DELETE CASCADE"
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS keys ("
            + "master_key_id INTEGER, "
            + "rank INTEGER, "

            + "key_id INTEGER, "
            + "key_size INTEGER, "
            + "key_curve_oid TEXT, "
            + "algorithm INTEGER, "
            + "fingerprint BLOB, "

            + "can_certify INTEGER, "
            + "can_sign INTEGER, "
            + "can_encrypt INTEGER, "
            + "can_authenticate INTEGER, "
            + "is_revoked INTEGER, "
            + "has_secret INTEGER, "

            + "creation INTEGER, "
            + "expiry INTEGER, "

            + "PRIMARY KEY(master_key_id, rank), "
            + "FOREIGN KEY(master_key_id) REFERENCES "
                + "keyrings_public(master_key_id) ON DELETE CASCADE "
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS user_packets("
            + "master_key_id INTEGER, "
            + "type INT, "
            + "user_id TEXT, "
            + "attribute_data BLOB, "

            + "is_primary INTEGER, "
            + "is_revoked INTEGER, "
            + "rank INTEGER, "

            + "PRIMARY KEY(master_key_id, rank), "
            + "FOREIGN KEY(master_key_id) REFERENCES "
                + "keyrings_public(master_key_id) ON DELETE CASCADE "
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS certs("
            + "master_key_id INTEGER, "
            + "rank INTEGER, " // rank of certified uid

            + "key_id_certifier INTEGER, " // certifying key
            + "type INTEGER, "
            + "verified INTEGER, "
            + "creation INTEGER, "

            + "data BLOB, "

            + "PRIMARY KEY(master_key_id, rank, key_id_certifier), "
            + "FOREIGN KEY(master_key_id) REFERENCES "
                + "keyrings_public(master_key_id) ON DELETE CASCADE, "
            + "FOREIGN KEY(master_key_id, rank) REFERENCES "
                + "user_packets(master_key_id, rank) ON DELETE CASCADE "
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS api_apps ("
            + "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            + "package_name TEXT NOT NULL UNIQUE, "
            + "package_signature BLOB"
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS api_accounts ("
            + "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            + "account_name TEXT NOT NULL, "
            + "key_id INTEGER, "
            + "encryption_algorithm INTEGER, "
            + "hash_algorithm INTEGER, "
            + "compression INTEGER, "
            + "package_name TEXT NOT NULL, "

            + "UNIQUE(account_name, package_name), "
            + "FOREIGN KEY(package_name) REFERENCES "
                + "api_apps(package_name) ON DELETE CASCADE"
        + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS api_allowed_keys ("
            + "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            + "key_id INTEGER, "
            + "package_name TEXT NOT NULL, "

            + "UNIQUE(key_id, package_name), "
            + "FOREIGN KEY(package_name) REFERENCES "
            + "api_apps(package_name) ON DELETE CASCADE"
        + ")");
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
        Log.d(Constants.TAG, "Upgrading db from " + oldVersion + " to " + newVersion);

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

            case 3:
                db.beginTransaction();
                try {
                    db.execSQL("DROP TABLE IF EXISTS keys");
                    db.execSQL("DROP TABLE IF EXISTS user_ids");
                    db.execSQL("DROP TABLE IF EXISTS api_apps");

                    db.execSQL("CREATE TABLE IF NOT EXISTS keyrings_public ("
                        + "master_key_id INTEGER PRIMARY KEY, "
                        + "key_ring_data BLOB "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS keyrings_secret ("
                        + "master_key_id INTEGER PRIMARY KEY, "
                        + "key_ring_data BLOB, "
                        + "FOREIGN KEY(master_key_id) "
                            + "REFERENCES keyrings_public(master_key_id) ON DELETE CASCADE "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS keys ("
                        + "master_key_id INTEGER, "
                        + "rank INTEGER, "

                        + "key_id INTEGER, "
                        + "key_size INTEGER, "
                        + "key_curve_oid TEXT, "
                        + "algorithm INTEGER, "
                        + "fingerprint BLOB, "

                        + "can_certify INTEGER, "
                        + "can_sign INTEGER, "
                        + "can_encrypt INTEGER, "
                        + "can_authenticate INTEGER, "
                        + "is_revoked INTEGER, "
                        + "has_secret INTEGER, "

                        + "creation INTEGER, "
                        + "expiry INTEGER, "

                        + "PRIMARY KEY(master_key_id, rank), "
                        + "FOREIGN KEY(master_key_id) REFERENCES "
                            + "keyrings_public(master_key_id) ON DELETE CASCADE "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS user_packets ("
                        + "master_key_id INTEGER, "
                        + "type INT, "
                        + "user_id TEXT, "
                        + "attribute_data BLOB, "

                        + "is_primary INTEGER, "
                        + "is_revoked INTEGER, "
                        + "rank INTEGER, "

                        + "PRIMARY KEY(master_key_id, rank), "
                        + "FOREIGN KEY(master_key_id) REFERENCES "
                            + "keyrings_public(master_key_id) ON DELETE CASCADE "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS certs ("
                        + "master_key_id INTEGER, "
                        + "rank INTEGER, " // rank of certified uid

                        + "key_id_certifier INTEGER, " // certifying key
                        + "type INTEGER, "
                        + "verified INTEGER, "
                        + "creation INTEGER, "

                        + "data BLOB, "

                        + "PRIMARY KEY(master_key_id, rank, key_id_certifier), "
                        + "FOREIGN KEY(master_key_id) REFERENCES "
                            + "keyrings_public(master_key_id) ON DELETE CASCADE, "
                        + "FOREIGN KEY(master_key_id, rank) REFERENCES "
                            + "user_packets(master_key_id, rank) ON DELETE CASCADE "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS api_apps ("
                        + "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        + "package_name TEXT NOT NULL UNIQUE, "
                        + "package_signature BLOB "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS api_accounts ("
                        + "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        + "account_name TEXT NOT NULL, "
                        + "key_id INTEGER, "
                        + "encryption_algorithm INTEGER, "
                        + "hash_algorithm INTEGER, "
                        + "compression INTEGER, "
                        + "package_name TEXT NOT NULL, "

                        + "UNIQUE(account_name, package_name), "
                        + "FOREIGN KEY(package_name) REFERENCES "
                            + "api_apps(package_name) ON DELETE CASCADE "
                    + ")");

                    db.execSQL("CREATE TABLE IF NOT EXISTS api_allowed_keys ("
                        + "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        + "key_id INTEGER, "
                        + "package_name TEXT NOT NULL, "

                        + "UNIQUE(key_id, package_name), "
                        + "FOREIGN KEY(package_name) REFERENCES "
                        + "api_apps(package_name) ON DELETE CASCADE "
                    + ")");

                    db.execSQL("INSERT INTO keyrings_public (master_key_id, key_ring_data) SELECT master_key_id, key_ring_data FROM key_rings WHERE type = 0");
                    db.execSQL("INSERT INTO keyrings_secret (master_key_id, key_ring_data) SELECT master_key_id, key_ring_data FROM key_rings WHERE type = 1");

                    db.setTransactionSuccessful();
                } finally {
                    db.endTransaction();
                }

                break;

            default:
                break;
            }
        }

        // always do consolidate after upgrade
        Intent consolidateIntent = new Intent(mContext.getApplicationContext(), ConsolidateDialogActivity.class);
        consolidateIntent.putExtra(ConsolidateDialogActivity.EXTRA_CONSOLIDATE_RECOVERY, false);
        consolidateIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        mContext.getApplicationContext().startActivity(consolidateIntent);
    }

    private static void copy(File in, File out) throws IOException {
        FileInputStream is = new FileInputStream(in);
        FileOutputStream os = new FileOutputStream(out);
        try {
            byte[] buf = new byte[512];
            while (is.available() > 0) {
                int count = is.read(buf, 0, 512);
                os.write(buf, 0, count);
            }
        } finally {
            is.close();
            os.close();
        }
    }

    public static void debugBackup(Context context, boolean restore) throws IOException {
        if (!Constants.DEBUG) {
            return;
        }

        File in;
        File out;
        if (restore) {
            in = context.getDatabasePath("debug_backup.db");
            out = context.getDatabasePath(DATABASE_NAME);
        } else {
            in = context.getDatabasePath(DATABASE_NAME);
            out = context.getDatabasePath("debug_backup.db");
            out.createNewFile();
        }
        if (!in.canRead()) {
            throw new IOException("Cannot read " +  in.getName());
        }
        if (!out.canWrite()) {
            throw new IOException("Cannot write " + out.getName());
        }
        copy(in, out);
    }

    // DANGEROUS, use in test code ONLY!
    public void clearDatabase() {
        getWritableDatabase().execSQL("delete from " + Tables.KEY_RINGS_PUBLIC);
    }

}
