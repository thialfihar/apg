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

package org.sufficientlysecure.keychain.provider;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.provider.BaseColumns;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.provider.KeychainContract.ApiAppsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.KeyRingsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.KeysColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.UserIdsColumns;
import org.sufficientlysecure.keychain.provider.KeychainContract.CertsColumns;
import org.sufficientlysecure.keychain.util.Log;

public class KeychainDatabase extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "apg.db";
    private static final int DATABASE_VERSION = 8;

    public interface Tables {
        String KEY_RINGS = "key_rings";
        String KEYS = "keys";
        String USER_IDS = "user_ids";
        String API_APPS = "api_apps";
        String CERTS = "certs";
    }

    private static final String CREATE_KEYRINGS_PUBLIC =
            "CREATE TABLE IF NOT EXISTS keyrings_public ("
                + KeyRingsColumns.MASTER_KEY_ID + " INTEGER PRIMARY KEY,"
                + KeyRingsColumns.KEY_RING_DATA + " BLOB"
            + ")";

    private static final String CREATE_KEYRINGS_SECRET =
            "CREATE TABLE IF NOT EXISTS keyrings_secret ("
                    + KeyRingsColumns.MASTER_KEY_ID + " INTEGER PRIMARY KEY,"
                    + KeyRingsColumns.KEY_RING_DATA + " BLOB,"
                    + "FOREIGN KEY(" + KeyRingsColumns.MASTER_KEY_ID + ") "
                        + "REFERENCES keyrings_public(" + KeyRingsColumns.MASTER_KEY_ID + ") ON DELETE CASCADE"
            + ")";

    private static final String CREATE_KEYS =
            "CREATE TABLE IF NOT EXISTS " + Tables.KEYS + " ("
                + KeysColumns.MASTER_KEY_ID + " INTEGER, "
                + KeysColumns.RANK + " INTEGER, "

                + KeysColumns.KEY_ID + " INTEGER, "
                + KeysColumns.KEY_SIZE + " INTEGER, "
                + KeysColumns.ALGORITHM + " INTEGER, "
                + KeysColumns.FINGERPRINT + " BLOB, "

                + KeysColumns.CAN_CERTIFY + " BOOLEAN, "
                + KeysColumns.CAN_SIGN + " BOOLEAN, "
                + KeysColumns.CAN_ENCRYPT + " BOOLEAN, "
                + KeysColumns.IS_REVOKED + " BOOLEAN, "

                + KeysColumns.CREATION + " INTEGER, "
                + KeysColumns.EXPIRY + " INTEGER, "

                + "PRIMARY KEY(" + KeysColumns.MASTER_KEY_ID + ", " + KeysColumns.RANK + "),"
                + "FOREIGN KEY(" + KeysColumns.MASTER_KEY_ID + ") REFERENCES "
                    + Tables.KEY_RINGS_PUBLIC + "(" + KeyRingsColumns.MASTER_KEY_ID + ") ON DELETE CASCADE"
            + ")";

    private static final String CREATE_USER_IDS =
            "CREATE TABLE IF NOT EXISTS " + Tables.USER_IDS + "("
                + UserIdsColumns.MASTER_KEY_ID + " INTEGER, "
                + UserIdsColumns.USER_ID + " CHARMANDER, "

                + UserIdsColumns.IS_PRIMARY + " BOOLEAN, "
                + UserIdsColumns.IS_REVOKED + " BOOLEAN, "
                + UserIdsColumns.RANK+ " INTEGER, "

                + "PRIMARY KEY(" + UserIdsColumns.MASTER_KEY_ID + ", " + UserIdsColumns.USER_ID + "), "
                + "UNIQUE (" + UserIdsColumns.MASTER_KEY_ID + ", " + UserIdsColumns.RANK + "), "
                + "FOREIGN KEY(" + UserIdsColumns.MASTER_KEY_ID + ") REFERENCES "
                    + Tables.KEY_RINGS_PUBLIC + "(" + KeyRingsColumns.MASTER_KEY_ID + ") ON DELETE CASCADE"
            + ")";

    private static final String CREATE_CERTS =
            "CREATE TABLE IF NOT EXISTS " + Tables.CERTS + "("
                + CertsColumns.MASTER_KEY_ID + " INTEGER,"
                + CertsColumns.RANK + " INTEGER, " // rank of certified uid

                + CertsColumns.KEY_ID_CERTIFIER + " INTEGER, " // certifying key
                + CertsColumns.TYPE + " INTEGER, "
                + CertsColumns.VERIFIED + " INTEGER, "
                + CertsColumns.CREATION + " INTEGER, "

                + CertsColumns.DATA + " BLOB, "

                + "PRIMARY KEY(" + CertsColumns.MASTER_KEY_ID + ", " + CertsColumns.RANK + ", "
                    + CertsColumns.KEY_ID_CERTIFIER + "), "
                + "FOREIGN KEY(" + CertsColumns.MASTER_KEY_ID + ") REFERENCES "
                    + Tables.KEY_RINGS_PUBLIC + "(" + KeyRingsColumns.MASTER_KEY_ID + ") ON DELETE CASCADE,"
                + "FOREIGN KEY(" + CertsColumns.MASTER_KEY_ID + ", " + CertsColumns.RANK + ") REFERENCES "
                    + Tables.USER_IDS + "(" + UserIdsColumns.MASTER_KEY_ID + ", " + UserIdsColumns.RANK + ") ON DELETE CASCADE"
            + ")";

    private static final String CREATE_API_APPS = "CREATE TABLE IF NOT EXISTS " + Tables.API_APPS
            + " (" + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + ApiAppsColumns.PACKAGE_NAME + " TEXT UNIQUE, "
            + ApiAppsColumns.PACKAGE_SIGNATURE + " BLOB, "
            + ApiAppsColumns.KEY_ID + " INT64, "
            + ApiAppsColumns.ENCRYPTION_ALGORITHM + " INTEGER, "
            + ApiAppsColumns.HASH_ALORITHM + " INTEGER, "
            + ApiAppsColumns.COMPRESSION + " INTEGER)";

    private static final String CREATE_CERTS = "CREATE TABLE IF NOT EXISTS " + Tables.CERTS
            + " (" + BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
            + CertsColumns.KEY_RING_ROW_ID + " INTEGER NOT NULL "
                + " REFERENCES " + Tables.KEY_RINGS + "(" + BaseColumns._ID + ") ON DELETE CASCADE, "
            + CertsColumns.KEY_ID + " INTEGER, " // certified key
            + CertsColumns.RANK + " INTEGER, " // key rank of certified uid
            + CertsColumns.KEY_ID_CERTIFIER + " INTEGER, " // certifying key
            + CertsColumns.CREATION + " INTEGER, "
            + CertsColumns.VERIFIED + " INTEGER, "
            + CertsColumns.KEY_DATA + " BLOB)";


    KeychainDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);

        // make sure this is only done once, on the first instance!
        boolean iAmIt = false;
        synchronized(apg_hack) {
            if(!apg_hack) {
                iAmIt = true;
                apg_hack = true;
            }
        }
        // if it's us, do the import
        if(iAmIt)
            checkAndImportApg(context);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.w(Constants.TAG, "Creating database...");

        db.execSQL(CREATE_KEY_RINGS);
        db.execSQL(CREATE_KEYS);
        db.execSQL(CREATE_USER_IDS);
        db.execSQL(CREATE_API_APPS);
        db.execSQL(CREATE_CERTS);
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
    public void onUpgrade(SQLiteDatabase db, int old, int nu) {
        // don't care (this is version 1)
    }

    /** This method tries to import data from a provided database.
     *
     * The sole assumptions made on this db are that there is a key_rings table
     * with a key_ring_data, a master_key_id and a type column, the latter of
     * which should be 1 for secret keys and 0 for public keys.
     */
    public void checkAndImportApg(Context context) {

        boolean hasApgDb = false; {
            // It's the Java way =(
            String[] dbs = context.databaseList();
            for(String db : dbs) {
                if(db.equals("apg.db")) {
                    hasApgDb = true;
                    break;
                case 4:
                    db.execSQL(CREATE_API_APPS);
                    break;
                case 5:
                    // new column: package_signature
                    db.execSQL("DROP TABLE IF EXISTS " + Tables.API_APPS);
                    db.execSQL(CREATE_API_APPS);
                    break;
                case 6:
                    // new column: fingerprint
                    db.execSQL("ALTER TABLE " + Tables.KEYS + " ADD COLUMN " + KeysColumns.FINGERPRINT
                            + " BLOB;");
                    break;
                case 7:
                    // new table: certs
                    db.execSQL(CREATE_CERTS);

                    break;
                default:
                    break;

        Cursor c = null;
        try {
            // we insert in two steps: first, all public keys that have secret keys
            c = db.rawQuery("SELECT key_ring_data FROM key_rings WHERE type = 1 OR EXISTS ("
                    + " SELECT 1 FROM key_rings d2 WHERE key_rings.master_key_id = d2.master_key_id"
                    + " AND d2.type = 1) ORDER BY type ASC", null);
            Log.d(Constants.TAG, "Importing " + c.getCount() + " secret keyrings from apg.db...");
            for(int i = 0; i < c.getCount(); i++) {
                c.moveToPosition(i);
                byte[] data = c.getBlob(0);
                PGPKeyRing ring = PgpConversionHelper.BytesToPGPKeyRing(data);
                if(ring instanceof PGPPublicKeyRing)
                    ProviderHelper.saveKeyRing(context, (PGPPublicKeyRing) ring);
                else if(ring instanceof PGPSecretKeyRing)
                    ProviderHelper.saveKeyRing(context, (PGPSecretKeyRing) ring);
                else {
                    Log.e(Constants.TAG, "Unknown blob data type!");
                }
            }

            // afterwards, insert all keys, starting with public keys that have secret keys, then
            // secret keys, then all others. this order is necessary to ensure all certifications
            // are recognized properly.
            c = db.rawQuery("SELECT key_ring_data FROM key_rings ORDER BY (type = 0 AND EXISTS ("
                    + " SELECT 1 FROM key_rings d2 WHERE key_rings.master_key_id = d2.master_key_id AND"
                    + " d2.type = 1)) DESC, type DESC", null);
            // import from old database
            Log.d(Constants.TAG, "Importing " + c.getCount() + " keyrings from apg.db...");
            for(int i = 0; i < c.getCount(); i++) {
                c.moveToPosition(i);
                byte[] data = c.getBlob(0);
                PGPKeyRing ring = PgpConversionHelper.BytesToPGPKeyRing(data);
                if(ring instanceof PGPPublicKeyRing)
                    ProviderHelper.saveKeyRing(context, (PGPPublicKeyRing) ring);
                else if(ring instanceof PGPSecretKeyRing)
                    ProviderHelper.saveKeyRing(context, (PGPSecretKeyRing) ring);
                else {
                    Log.e(Constants.TAG, "Unknown blob data type!");
                }
            }
        }
    }

}
