#!/bin/bash

rsync -aru ../OpenKeychain/src/main/./assets src/main
rsync -aru ../OpenKeychain/src/main/./res src/main
rsync -aru ../OpenKeychain/src/main/./java src/main

find src/main/java -iname '*.java' -exec perl -pi -e 's/"OpenKeychain"/"APG"/g' {} \;
find src/main/java -iname '*.java' -exec perl -pi -e 's/"Keychain"/"APG"/g' {} \;
find src/main/res -type f ! -iname '*help*' -exec perl -pi -e 's/OpenKeychain/APG/g' {} \;

find src/main -type f -exec perl -pi -e 's/sufficientlysecure[.]keychain[.](R|BuildConfig)/thialfihar.android.apg.\1/g' {} \;
