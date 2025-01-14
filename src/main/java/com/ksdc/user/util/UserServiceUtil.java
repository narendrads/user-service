package com.ksdc.user.util;

import java.util.function.Supplier;

import org.springframework.stereotype.Component;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

@Component
public class UserServiceUtil {
	private static final Gson GSON = new GsonBuilder().create();

    public static String jsonAsString(Object obj) {
        return obj == null ? "null" : handle(() -> GSON.toJson(obj), "Error serializing object");
    }

    private static <T> T handle(Supplier<T> action, String errorMessage) {
        try {
            return action.get();
        } catch (Exception e) {
            throw new IllegalStateException(errorMessage, e);
        }
    }
}
