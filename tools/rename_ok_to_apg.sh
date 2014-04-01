#!/bin/sh
perl -pi -e 's/OpenKeychain/APG/g' $@
perl -pi -e 's/KeychainI/ApgI/g' $@
perl -pi -e 's/sufficientlysecure.keychain/thialfihar.android.apg/g' $@

