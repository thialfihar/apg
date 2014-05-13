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
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.pgp.KeyRing;
import org.thialfihar.android.apg.provider.ProviderHelper;
import org.thialfihar.android.apg.util.Log;

import java.io.IOException;

public class ApgDatabase extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "apg.db";
    private static final int DATABASE_VERSION = 1;

    static Boolean migrationHack = false;

    private Context mContext;

    public interface Tables {
        String KEY_RINGS_PUBLIC = "keyrings_public";
        String KEY_RINGS_SECRET = "keyrings_secret";
        String KEYS = "keys";
        String USER_IDS = "user_ids";
        String CERTS = "certs";
        String API_APPS = "api_apps";
        String API_ACCOUNTS = "api_accounts";
    }

    ApgDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        mContext = context;
        // make sure this is only done once, on the first instance!
        boolean iAmIt = false;
        synchronized(migrationHack) {
            if (!migrationHack) {
                iAmIt = true;
                migrationHack = true;
            }
        }

        // if it's us, do the import
        if (iAmIt) {
            migrateDatabase();
        }
    }

    void migrateDatabase() {
        boolean hasApgDb = false;

        for (String db : mContext.databaseList()) {
            if (db.equals("apg")) {
                hasApgDb = true;
            } else if (db.equals("apg_old.db")) {
                Log.d(Constants.TAG, "Found apg_old.db");
            }
        }

        if (!hasApgDb) {
            return;
        }

        Log.d(Constants.TAG, "apg exists! Migrating...");

        SQLiteDatabase db = new SQLiteOpenHelper(mContext, "apg", null, 1) {
            @Override
            public void onCreate(SQLiteDatabase db) {
                // should never happen
                throw new AssertionError();
            }
            @Override
            public void onDowngrade(SQLiteDatabase db, int old, int nu) {
                // don't care
            }
            @Override
            public void onUpgrade(SQLiteDatabase db, int old, int nu) {
                // don't care either
            }
        }.getReadableDatabase();

        Cursor cursor = null;
        ProviderHelper providerHelper = new ProviderHelper(mContext);

        try {
            String query;
            int version = 2;
            cursor = db.rawQuery("SELECT * FROM key_rings", null);
            if (cursor != null) {
                for (int i= 0; i < cursor.getColumnCount(); ++i) {
                    if (cursor.getColumnName(i).equals("c_master_key_id")) {
                        version = 1;
                        break;
                    }
                }
            }
            // public keyrings that have secret key rings first, then secret key rings
            if (version == 1) {
                query = "SELECT c_key_ring_data FROM key_rings WHERE c_type = 1 OR EXISTS (" +
                    " SELECT 1 FROM key_rings d2 WHERE key_rings.c_master_key_id = d2.c_master_key_id" +
                    " AND d2.c_type = 1) ORDER BY c_type ASC";
            } else {
                query = "SELECT key_ring_data FROM key_rings WHERE type = 1 OR EXISTS (" +
                    " SELECT 1 FROM key_rings d2 WHERE key_rings.master_key_id = d2.master_key_id" +
                    " AND d2.type = 1) ORDER BY type ASC";
            }
            // we insert in two steps: first, all public keys that have secret keys
            cursor = db.rawQuery(query, null);
            if (cursor != null) {
                Log.d(Constants.TAG, "Migrating " + cursor.getCount() + " secret keyrings from apg...");
                for (int i = 0; i < cursor.getCount(); i++) {
                    cursor.moveToPosition(i);
                    byte[] data = cursor.getBlob(0);
                    KeyRing keyRing = KeyRing.decode(data);
                    providerHelper.saveKeyRing(keyRing);
                }
                cursor.close();
            }

            // afterwards, insert all keys, starting with public keys that have secret keys, then
            // secret keys, then all others. this order is necessary to ensure all certifications
            if (version == 1) {
                query = "SELECT c_key_ring_data FROM key_rings ORDER BY (c_type = 0 AND EXISTS (" +
                    " SELECT 1 FROM key_rings d2 WHERE key_rings.c_master_key_id = d2.c_master_key_id AND" +
                    " d2.c_type = 1)) DESC, c_type DESC";
            } else {
                query = "SELECT key_ring_data FROM key_rings ORDER BY (type = 0 AND EXISTS (" +
                    " SELECT 1 FROM key_rings d2 WHERE key_rings.master_key_id = d2.master_key_id AND" +
                    " d2.type = 1)) DESC, type DESC";
            }
             // are recognized properly.
            cursor = db.rawQuery(query, null);

            if (cursor != null) {
            Log.d(Constants.TAG, "Migrating " + cursor.getCount() + " keyrings from apg...");
                for (int i = 0; i < cursor.getCount(); i++) {
                    cursor.moveToPosition(i);
                    byte[] data = cursor.getBlob(0);
                    KeyRing keyRing = KeyRing.decode(data);
                    providerHelper.saveKeyRing(keyRing);
                }
            }
        } catch (IOException e) {
            Log.e(Constants.TAG, "Error migrating apg!", e);
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }

        // Move to a different file (but don't delete, just to be safe)
        Log.d(Constants.TAG, "All done - moving apg to apg_old.db");
        mContext.getDatabasePath("apg").renameTo(mContext.getDatabasePath("apg_old.db"));
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.w(Constants.TAG, "Creating database...");

        db.execSQL("CREATE TABLE IF NOT EXISTS keyrings_public(" +
            "master_key_id INTEGER PRIMARY KEY," +
            "key_ring_data BLOB);");

        db.execSQL("CREATE TABLE IF NOT EXISTS keyrings_secret(" +
            "master_key_id INTEGER PRIMARY KEY," +
            "key_ring_data BLOB," +
            "FOREIGN KEY(master_key_id) " +
                "REFERENCES keyrings_public(master_key_id) ON DELETE CASCADE)");

        db.execSQL("CREATE TABLE IF NOT EXISTS keys(" +
            "master_key_id INTEGER, " +
            "rank INTEGER, " +
            "key_id INTEGER, " +
            "key_size INTEGER, " +
            "algorithm INTEGER, " +
            "fingerprint BLOB, " +
            "can_certify BOOLEAN, " +
            "can_sign BOOLEAN, " +
            "can_encrypt BOOLEAN, " +
            "is_revoked BOOLEAN, " +
            "has_secret BOOLEAN, " +
            "creation INTEGER, " +
            "expiry INTEGER, " +
            "PRIMARY KEY(master_key_id, rank), " +
            "FOREIGN KEY(master_key_id) REFERENCES " +
                "keyrings_public(master_key_id) ON DELETE CASCADE)");

        db.execSQL("CREATE TABLE IF NOT EXISTS user_ids(" +
            "master_key_id INTEGER, " +
            "user_id TEXT, " +
            "is_primary BOOLEAN, " +
            "is_revoked BOOLEAN, " +
            "rank INTEGER, " +
            "PRIMARY KEY(master_key_id, user_id), " +
            "UNIQUE (master_key_id, rank), " +
            "FOREIGN KEY(master_key_id) REFERENCES " +
                "keyrings_public(master_key_id) ON DELETE CASCADE)");

        db.execSQL("CREATE TABLE api_apps(" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "package_name TEXT NOT NULL UNIQUE, " +
            "package_signature BLOB)");

        db.execSQL("CREATE TABLE IF NOT EXISTS api_accounts(" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "account_name TEXT NOT NULL, " +
            "key_id INT64, " +
            "encryption_algorithm INTEGER, " +
            "hash_algorithm INTEGER, " +
            "compression INTEGER, " +
            "package_name TEXT NOT NULL, " +
            "UNIQUE(account_name, package_name), " +
            "FOREIGN KEY(package_name) REFERENCES api_apps(package_name) ON DELETE CASCADE)");

        db.execSQL("CREATE TABLE IF NOT EXISTS certs(" +
            "master_key_id INTEGER, " +
            "rank INTEGER, " +
            "key_id_certifier INTEGER, " +
            "type INTEGER, " +
            "verified INTEGER, " +
            "creation INTEGER, " +
            "data BLOB, " +
            "PRIMARY KEY(master_key_id, rank, key_id_certifier), " +
            "FOREIGN KEY(master_key_id) REFERENCES " +
                    "keyrings_public(master_key_id) ON DELETE CASCADE," +
            "FOREIGN KEY(master_key_id, rank) REFERENCES " +
                    "user_ids(master_key_id, rank) ON DELETE CASCADE)");
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
    }
}
