package com.wustrive.aesrsa.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.*;

public class AESRSAUtils {
//    private static String serverPublicKey=null;
    private static String clientPublicKey=null;
    private static String clientPrivateKey=null;
    private static OkHttpConfig okHttpConfig;
    private static Map<String,String> serverPublicKeys;

    static{
        Properties properties = new Properties();
        try {
            properties.load(AESRSAUtils.class.getClassLoader().getResourceAsStream("RSAKeys.properties"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        serverPublicKeys=new HashMap<String,String>();
        if(properties.getProperty("serverHosts")!=null && !properties.getProperty("serverHosts").isEmpty()){
            String[] serverHosts=properties.getProperty("serverHosts").split(" ");
            for(int hostIndex=0;hostIndex<serverHosts.length;hostIndex++){
                serverPublicKeys.put(serverHosts[hostIndex],properties.getProperty("serverPublicKey."+ (hostIndex+1)));
            }
        }
//        String[] serverHosts=properties.getProperty("serverHosts").split(" ");
//        for(int hostIndex=0;hostIndex<serverHosts.length;hostIndex++){
//            serverPublicKeys.put(serverHosts[hostIndex],properties.getProperty("serverPublicKey."+ (hostIndex+1)));
//        }
//        serverPublicKeys.put("csfz.cn",properties.getProperty("serverPublicKey"));
//        serverPublicKey=properties.getProperty("serverPublicKey");
        clientPrivateKey=properties.getProperty("privateKey");
        clientPublicKey=properties.getProperty("publicKey");
        if(clientPublicKey==null || clientPrivateKey==null){
            try {
                Map<String, String> map= RSA.generateKeyPair();
                clientPrivateKey = map.get("privateKey");
                clientPublicKey = map.get("publicKey");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        okHttpConfig=new OkHttpConfig();
    }

    public static <T> String sendMessage(String url,T t) throws Exception{
        String json = GsonUtils.getJsonByObject(t);
        TreeMap<String, Object> params = new TreeMap<String, Object>();
        params.put("data",json);
        params.put("publicKey",clientPublicKey);
        String sign = EncryUtil.handleRSA(params,clientPrivateKey);
        params.put("sign",sign);

        String info= JSON.toJSONString(params);
        String aesKey = SecureRandomUtil.getRandom(16);
        String data = AES.encryptToBase64(ConvertUtils.stringToHexString(info),aesKey);

        String encryptkey = RSA.encrypt(aesKey,serverPublicKeys.get(new URL(url).getHost()));

        FormBody formBody=new FormBody.Builder().add("data",data).build();
        Request request=new Request.Builder().url(url).addHeader("aesKey",encryptkey).post(formBody).build();

        String returnData="";
        OkHttpClient okHttpClient=okHttpConfig.okHttpClient();
        Response response = okHttpClient.newCall(request).execute();
        return response.body().string();
    }


    public static <T> T decryptMessage(String ciphertext,String encryptkey,String host,Class<T> clz) throws Exception{
        String serverPublicKey = serverPublicKeys.get(host);
        if(serverPublicKey == null){
            String tmpAESKey=RSA.decrypt(encryptkey,clientPrivateKey);
            String tmpInfo=ConvertUtils.hexStringToString(AES.decryptFromBase64(ciphertext,tmpAESKey));
            JSONObject tmpJSONObject= JSON.parseObject(tmpInfo);
            serverPublicKey = tmpJSONObject.getString("publicKey");
        }
        boolean passSign = EncryUtil.checkDecryptAndSign(ciphertext,encryptkey,serverPublicKey,clientPrivateKey);
        if(passSign){
            String aesKey = RSA.decrypt(encryptkey,clientPrivateKey);
            String data = ConvertUtils.hexStringToString(AES.decryptFromBase64(ciphertext,aesKey));

            JSONObject jsonObject = JSONObject.parseObject(data);
            String json = jsonObject.getString("data");
            storeProperties();
            return  GsonUtils.getObjectByJson(json,clz);
        }else {
            serverPublicKeys.put(host,null);
        }



        return null;
    }

    private static void storeProperties(){
        Properties properties = new Properties();
        properties.setProperty("privateKey",clientPrivateKey);
        properties.setProperty("publicKey",clientPublicKey);
        String serverHosts="";
        int hostIndex=0;
        for(Map.Entry<String,String> entry:serverPublicKeys.entrySet()){
            if(entry.getValue() != null){
                serverHosts += entry.getKey()+" ";
                properties.setProperty("serverPublicKey."+(++hostIndex),entry.getValue());
            }
        }
        properties.setProperty("serverHosts",serverHosts);

        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(AESRSAUtils.class.getClassLoader().getResource("RSAKeys.properties").getPath());
            properties.store(fileOutputStream,new Date().toString());
            fileOutputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
