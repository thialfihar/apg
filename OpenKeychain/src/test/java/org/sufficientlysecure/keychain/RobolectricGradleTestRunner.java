package org.thialfihar.android.apg;

import org.junit.runners.model.InitializationError;
import org.robolectric.AndroidManifest;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.res.Fs;
import org.robolectric.res.FsFile;

import org.thialfihar.android.apg.KeychainApplication;

public class RobolectricGradleTestRunner extends RobolectricTestRunner {
    public RobolectricGradleTestRunner(Class<?> testClass) throws InitializationError {
        super(testClass);
    }

    @Override protected AndroidManifest getAppManifest(Config config) {
        String myAppPath = KeychainApplication.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        String manifestPath = myAppPath + "../../../src/main/AndroidManifest.xml";
        return createAppManifest(Fs.fileFromPath(manifestPath));
    }
}

