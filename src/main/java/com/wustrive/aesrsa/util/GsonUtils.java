package com.wustrive.aesrsa.util;

import com.google.gson.Gson;

public class GsonUtils {
    private static Gson gson=null;

    private static Gson getGson(){
        if(gson==null){
            gson = new Gson();
        }
        return gson;
    }

    public static <T> T getObjectByJson(String json,Class<T> clz){
        return getGson().fromJson(json,clz);
    }

    public static <T> String getJsonByObject(T t){
        return getGson().toJson(t);
    }
}
