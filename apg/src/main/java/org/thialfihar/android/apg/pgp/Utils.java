/*
 * Copyright (C) 2012-2013 Dominik Schürmann <dominik@dominikschuermann.de>
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

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {

    private static final Pattern USER_ID_PATTERN = Pattern.compile("^(.*?)(?: \\((.*)\\))?(?: <(.*)>)?$");

    /**
     * Converts fingerprint to hex with whitespaces after 4 characters
     *
     * @param fp
     * @return
     */
    public static String convertFingerprintToHex(byte[] fp, boolean chunked) {
        String fingerPrint = "";
        for (int i = 0; i < fp.length; ++i) {
            if (chunked && i != 0 && i % 10 == 0) {
                fingerPrint += "  ";
            } else if (chunked && i != 0 && i % 2 == 0) {
                fingerPrint += " ";
            }
            String chunk = Integer.toHexString((fp[i] + 256) % 256).toUpperCase(Locale.US);
            while (chunk.length() < 2) {
                chunk = "0" + chunk;
            }
            fingerPrint += chunk;
        }

        return fingerPrint;

    }

    public static String toHex(long keyId, int length) {
        String hex = Long.toHexString(keyId).toUpperCase(Locale.US);
        while (hex.length() < length) {
            hex = "0" + hex;
        }
        return hex.substring(hex.length() - length, hex.length());
    }

    public static long convertHexToKeyId(String data) {
        int len = data.length();
        String s2 = data.substring(len - 8);
        String s1 = data.substring(0, len - 8);
        return (Long.parseLong(s1, 16) << 32) | Long.parseLong(s2, 16);
    }

    /**
     * Splits userId string into naming part, email part, and comment part
     *
     * @param userId
     * @return array with naming (0), email (1), comment (2)
     */
    public static String[] splitUserId(String userId) {
        String[] result = new String[] { null, null, null };

        if (userId == null || userId.equals("")) {
            return result;
        }

        /*
         * User ID matching:
         * http://fiddle.re/t4p6f
         *
         * test cases:
         * "Max Mustermann (this is a comment) <max@example.com>"
         * "Max Mustermann <max@example.com>"
         * "Max Mustermann (this is a comment)"
         * "Max Mustermann [this is nothing]"
         */
        Matcher matcher = USER_ID_PATTERN.matcher(userId);
        if (matcher.matches()) {
            result[0] = matcher.group(1);
            result[1] = matcher.group(3);
            result[2] = matcher.group(2);
            return result;
        }

        return result;
    }


    public static int[] getRgbForData(byte[] bytes) throws NoSuchAlgorithmException, DigestException {
        MessageDigest md = MessageDigest.getInstance("SHA1");

        md.update(bytes);
        byte[] digest = md.digest();
        int[] result = {((int) digest[0] + 256) % 256,
                        ((int) digest[1] + 256) % 256,
                        ((int) digest[2] + 256) % 256};
        return result;
    }
}
