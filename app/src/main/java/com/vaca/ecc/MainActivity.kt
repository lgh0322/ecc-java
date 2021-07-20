package com.vaca.ecc

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.vaca.ecc.sm.TestSM2
import java.lang.Exception

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        TestSM2.mainX()
    }
}