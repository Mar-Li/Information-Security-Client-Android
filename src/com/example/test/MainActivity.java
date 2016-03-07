package com.example.test;

import android.app.Activity;
import android.os.Bundle;

import java.io.File;

public class MainActivity extends Activity {
    /**
     * Called when the activity is first created.
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        String path = new File("").getAbsolutePath();
    }
}
