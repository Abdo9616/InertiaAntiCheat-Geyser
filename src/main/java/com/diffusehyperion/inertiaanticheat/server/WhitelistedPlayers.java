package com.diffusehyperion.inertiaanticheat.server;

import com.diffusehyperion.inertiaanticheat.common.InertiaAntiCheat;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class WhitelistedPlayers {
    private static final Path FILE_PATH = InertiaAntiCheat.getConfigDir().resolve("whitelisted_players.json");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Object LOAD_LOCK = new Object();

    private static volatile boolean enabled = false;
    private static volatile Set<String> names = Set.of();
    private static volatile long lastModified = Long.MIN_VALUE;

    private WhitelistedPlayers() {
    }

    static void initialize() {
        ensureLoaded(true);
    }

    static boolean isWhitelisted(String playerName) {
        if (playerName == null || playerName.isBlank()) {
            return false;
        }
        ensureLoaded(false);
        if (!enabled) {
            return false;
        }
        return names.contains(normalizeName(playerName));
    }

    private static void ensureLoaded(boolean forceReload) {
        long currentLastModified = getLastModified();
        if (!forceReload && currentLastModified == lastModified) {
            return;
        }

        synchronized (LOAD_LOCK) {
            currentLastModified = getLastModified();
            if (!forceReload && currentLastModified == lastModified) {
                return;
            }
            loadFromDisk();
        }
    }

    private static void loadFromDisk() {
        try {
            Files.createDirectories(InertiaAntiCheat.getConfigDir());
            if (!Files.exists(FILE_PATH)) {
                writeDefaultFile();
            }

            WhitelistConfig config = readConfig();
            if (config == null) {
                enabled = false;
                names = Set.of();
                lastModified = getLastModified();
                return;
            }

            enabled = config.enabled;
            names = normalizeNames(config.players);
            lastModified = getLastModified();
        } catch (IOException e) {
            InertiaAntiCheat.error("Failed to load whitelisted_players.json: " + e.getMessage());
            enabled = false;
            names = Set.of();
            lastModified = Long.MIN_VALUE;
        }
    }

    private static void writeDefaultFile() throws IOException {
        WhitelistConfig defaultConfig = new WhitelistConfig();
        try (Writer writer = Files.newBufferedWriter(FILE_PATH, StandardCharsets.UTF_8)) {
            GSON.toJson(defaultConfig, writer);
            writer.write(System.lineSeparator());
        }
        InertiaAntiCheat.info("Created default whitelisted_players.json at " + FILE_PATH);
    }

    private static WhitelistConfig readConfig() throws IOException {
        try (Reader reader = Files.newBufferedReader(FILE_PATH, StandardCharsets.UTF_8)) {
            WhitelistConfig config = GSON.fromJson(reader, WhitelistConfig.class);
            return config == null ? new WhitelistConfig() : config;
        } catch (JsonParseException e) {
            InertiaAntiCheat.error("Invalid JSON in whitelisted_players.json. Whitelist is disabled until the file is fixed.");
            return null;
        }
    }

    private static Set<String> normalizeNames(List<String> players) {
        if (players == null || players.isEmpty()) {
            return Set.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String player : players) {
            String value = normalizeName(player);
            if (!value.isEmpty()) {
                normalized.add(value);
            }
        }
        return Set.copyOf(normalized);
    }

    private static String normalizeName(String playerName) {
        return playerName == null ? "" : playerName.trim().toLowerCase(Locale.ROOT);
    }

    private static long getLastModified() {
        try {
            if (!Files.exists(FILE_PATH)) {
                return -1L;
            }
            return Files.getLastModifiedTime(FILE_PATH).toMillis();
        } catch (IOException e) {
            return Long.MIN_VALUE;
        }
    }

    private static final class WhitelistConfig {
        private boolean enabled = false;
        private List<String> players = List.of();
    }
}
