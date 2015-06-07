#!/bin/bash

rsync -aru ../OpenKeychain/src/main/./assets src/main
rsync -aru ../OpenKeychain/src/main/./res src/main

mkdir -p src/main/java/org/thialfihar/android/apg
rsync -aru ../OpenKeychain/src/main/java/./android src/main/java
rsync -aru ../OpenKeychain/src/main/java/org/./spongycastle src/main/java/org
rsync -aru ../OpenKeychain/src/main/java/org/sufficientlysecure/keychain/./ src/main/java/org/thialfihar/android/apg

find src/main -type f -exec perl -pi -e 's/sufficientlysecure[.]keychain(?![.]intents)/thialfihar.android.apg/g' {} \;
find src/main/java -iname '*.java' -exec perl -pi -e 's/"OpenKeychain"/"APG"/g' {} \;
find src/main/java -iname '*.java' -exec perl -pi -e 's/"Keychain"/"APG"/g' {} \;
find src/main/res -type f ! -iname '*changelog*' ! -iname '*help*' -exec perl -pi -e 's/OpenKeychain/APG/g' {} \;
find src/main/res -type f ! -iname '*help*' -exec perl -pi -e 's/OpenKeychain/APG/g' {} \;
