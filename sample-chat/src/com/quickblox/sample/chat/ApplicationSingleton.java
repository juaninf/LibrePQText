package com.quickblox.sample.chat;

import android.app.Application;
import android.provider.Settings.Secure;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.telephony.TelephonyManager;

import com.quickblox.core.QBSettings;

public class ApplicationSingleton extends Application {
    private static final String TAG = ApplicationSingleton.class.getSimpleName();
    private static final String JUAN = "JUAN";
    public static final String APP_ID = "23448";
    public static final String AUTH_KEY = "Fj2dj8OML-fPRyu";
    public static final String AUTH_SECRET = "xrw9jXQmQSBFL9O";

    public static String USER_LOGIN = "july";
    public static String USER_PASSWORD = "peru2006";

    private static ApplicationSingleton instance;
    public static ApplicationSingleton getInstance() {
        return instance;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        Log.d(TAG, "onCreate");

        instance = this;

        // Initialise QuickBlox SDK
        //
        final TelephonyManager tm = (TelephonyManager) getBaseContext().getSystemService(Context.TELEPHONY_SERVICE);

        final String tmDevice, tmSerial, androidId;
        tmDevice = "" + tm.getDeviceId();
        tmSerial = "" + tm.getSimSerialNumber();
        androidId = "" + android.provider.Settings.Secure.getString(getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        if(androidId.equals("76f333647e7622ae")){
        	this.USER_LOGIN = "juan";
            this.USER_PASSWORD = "peru2006";
        }
        Log.d(JUAN, "android_id"+androidId);
        QBSettings.getInstance().fastConfigInit(APP_ID, AUTH_KEY, AUTH_SECRET);

    }

    public int getAppVersion() {
        try {
            PackageInfo packageInfo = getPackageManager().getPackageInfo(getPackageName(), 0);
            return packageInfo.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            // should never happen
            throw new RuntimeException("Could not get package name: " + e);
        }
    }
}
