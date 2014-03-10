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

package org.thialfihar.android.apg.pgp;

import org.spongycastle.openpgp.PGPPublicKeyRing;

public class PublicKeyRing extends KeyRing {
    public PublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        super(publicKeyRing);
    }

    public PublicKeyRing(KeyRing keyRing) {
        super(keyRing.getPublicKeyRing());
    }
}
