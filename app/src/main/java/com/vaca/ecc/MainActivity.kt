package com.vaca.ecc

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.vaca.ecc.sm.SM2
import com.vaca.ecc.sm.SM2Utils
import com.vaca.ecc.sm.SM2Utils.x1
import com.vaca.ecc.sm.SM2Utils.x2
import com.vaca.ecc.sm.TestSM2
import java.lang.Exception

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        SM2Utils.generateKeyPair()
        TestSM2.mainX(x2,x1)
    }
}