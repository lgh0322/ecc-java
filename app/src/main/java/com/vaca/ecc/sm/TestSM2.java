package com.vaca.ecc.sm;

import java.io.*;

/**
 * @Description:
 * @Author: 陈欢
 * @Date: 2018/10/23 14:18
 */
public class TestSM2 {
    public static void mainX( String prik, String pubk) throws Exception {
        String plainText = "1122334455667788";
        byte[] datas = plainText.getBytes();

        byte[] cipherText = SM2Utils.encrypt(Util.hexStringToBytes(pubk), datas);
        System.out.println(Util.encodeHexString(cipherText));
        System.out.println("");

        String data = Util.encodeHexString(cipherText);
        byte[] decrypt = SM2Utils.decrypt(Util.hexStringToBytes(prik), Util.hexStringToBytes(data));

        System.out.println("解密: "+new String(decrypt) );

    }
}
