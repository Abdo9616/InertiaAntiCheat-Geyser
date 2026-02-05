package com.diffusehyperion.inertiaanticheat.server;

import java.lang.reflect.Method;
import java.util.UUID;

final class FloodgateBridge {
    private static final String API_CLASS_NAME = "org.geysermc.floodgate.api.FloodgateApi";
    private static final FloodgateBridge INSTANCE = new FloodgateBridge();

    private final Object initLock = new Object();

    private volatile boolean available;
    private volatile Object apiInstance;
    private volatile Method isFloodgateByUuid;
    private volatile Method getPlayerByUuid;

    static FloodgateBridge get() {
        return INSTANCE;
    }

    private FloodgateBridge() {
    }

    boolean isAvailable() {
        return ensureAvailable();
    }

    boolean isFloodgatePlayer(UUID uuid) {
        if (!ensureAvailable()) {
            return false;
        }
        if (uuid != null && invokeBoolean(isFloodgateByUuid, uuid)) {
            return true;
        }
        if (uuid != null && invokeGetPlayer(getPlayerByUuid, uuid)) {
            return true;
        }
        return false;
    }

    private boolean ensureAvailable() {
        if (available) {
            return true;
        }
        synchronized (initLock) {
            if (available) {
                return true;
            }
            tryInit();
            return available;
        }
    }

    private void tryInit() {
        Object api = null;
        Method isByUuid = null;
        Method getByUuid = null;

        try {
            Class<?> apiClass = Class.forName(API_CLASS_NAME);
            api = apiClass.getMethod("getInstance").invoke(null);
            isByUuid = getMethod(apiClass, "isFloodgatePlayer", UUID.class);
            getByUuid = getMethod(apiClass, "getPlayer", UUID.class);
        } catch (Exception e) {
            // ignore, we'll report unavailable
        }

        this.apiInstance = api;
        this.isFloodgateByUuid = isByUuid;
        this.getPlayerByUuid = getByUuid;
        this.available = api != null;
    }

    private boolean invokeBoolean(Method method, Object arg) {
        if (method == null) {
            return false;
        }
        try {
            Object result = method.invoke(apiInstance, arg);
            return result instanceof Boolean && (Boolean) result;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean invokeGetPlayer(Method method, Object arg) {
        if (method == null) {
            return false;
        }
        try {
            return method.invoke(apiInstance, arg) != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static Method getMethod(Class<?> apiClass, String name, Class<?> param) {
        try {
            return apiClass.getMethod(name, param);
        } catch (Exception e) {
            return null;
        }
    }
}
