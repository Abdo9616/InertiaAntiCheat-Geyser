package com.diffusehyperion.inertiaanticheat.common;

import com.diffusehyperion.inertiaanticheat.common.util.HashAlgorithm;
import com.diffusehyperion.inertiaanticheat.server.InertiaAntiCheatServer;
import com.moandjiezana.toml.Toml;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.network.PacketByteBuf;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static com.diffusehyperion.inertiaanticheat.common.util.InertiaAntiCheatConstants.MODLOGGER;

public class InertiaAntiCheat implements ModInitializer {

    @Override
    public void onInitialize() {
        info("Initializing InertiaAntiCheat!");
        try {
            Files.createDirectories(getConfigDir());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void info(String info) {MODLOGGER.info("[InertiaAntiCheat] {}", info);}
    public static void warn(String info) {MODLOGGER.warn("[InertiaAntiCheat] {}", info);}
    public static void error(String info) {MODLOGGER.error("[InertiaAntiCheat] {}", info);}

    public static String getHash(byte[] input, HashAlgorithm algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.toString());
            byte[] hash = md.digest(input);
            StringBuilder hashBuilder = new StringBuilder(new BigInteger(1, hash).toString(16));
            while (hashBuilder.length() < algorithm.getLength()) {
                hashBuilder.insert(0, "0");
            }
            return hashBuilder.toString();
        } catch (NoSuchAlgorithmException e){
            throw new RuntimeException("Invalid algorithm provided! Please report this on this project's Github!", e);
        }
    }

    public static Toml initializeConfig(String defaultConfigPath, Long currentConfigVersion) {
        File configFile = getConfigDir().resolve("./InertiaAntiCheat.toml").toFile();
        if (!configFile.exists()) {
            warn("No config file found! Creating a new one now...");
            try {
                Files.copy(Objects.requireNonNull(InertiaAntiCheatServer.class.getResourceAsStream(defaultConfigPath)), configFile.toPath());
            } catch (IOException e) {
                throw new RuntimeException("Couldn't a create default config!", e);
            }
        }
        Toml config = new Toml().read(configFile);
        boolean versionMismatch = !Objects.equals(config.getLong("debug.version", 0L), currentConfigVersion);
        boolean patched = patchTomlConfig(configFile, defaultConfigPath, currentConfigVersion, versionMismatch);
        if (patched) {
            config = new Toml().read(configFile);
            info("Done! Your config was patched with new defaults (existing values preserved).");
        }

        return config;
    }

    private static boolean patchTomlConfig(File configFile, String defaultConfigPath,
            Long currentConfigVersion, boolean versionMismatch) {
        List<String> existingLines;
        List<String> defaultLines;
        try {
            existingLines = Files.readAllLines(configFile.toPath(), StandardCharsets.UTF_8);
            defaultLines = readDefaultConfigLines(defaultConfigPath);
        } catch (IOException e) {
            throw new RuntimeException("Couldn't read config file!", e);
        }

        ExistingToml existing = parseExistingToml(existingLines);
        List<TomlTemplateSection> templateSections = parseTemplateSections(defaultLines);
        List<String> additions = buildMissingBlocks(existing, templateSections, currentConfigVersion);

        boolean modified = false;
        if (!additions.isEmpty()) {
            if (!existingLines.isEmpty() && !existingLines.get(existingLines.size() - 1).isBlank()) {
                existingLines.add("");
            }
            existingLines.addAll(additions);
            modified = true;
        }

        boolean versionUpdated = updateDebugVersion(existingLines, currentConfigVersion);
        modified |= versionUpdated;

        if (!modified) {
            return false;
        }

        if (versionMismatch) {
            warn("Looks like your config file is outdated! Backing up current config, then patching it.");
            warn("Your config file will be backed up to \"BACKUP-InertiaAntiCheat.toml\".");
            File backupFile = getConfigDir().resolve("BACKUP-InertiaAntiCheat.toml").toFile();
            try {
                Files.copy(configFile.toPath(), backupFile.toPath());
            } catch (IOException e) {
                throw new RuntimeException("Couldn't copy existing config file into a backup config file! Please do it manually.", e);
            }
        }

        try {
            Files.write(configFile.toPath(), existingLines, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Couldn't write updated config file!", e);
        }

        return true;
    }

    private static List<String> readDefaultConfigLines(String defaultConfigPath) throws IOException {
        try (InputStream stream = InertiaAntiCheatServer.class.getResourceAsStream(defaultConfigPath)) {
            if (stream == null) {
                throw new RuntimeException("Default config resource not found: " + defaultConfigPath);
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        }
    }

    private static ExistingToml parseExistingToml(List<String> lines) {
        ExistingToml existing = new ExistingToml();
        String currentSection = "";
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                continue;
            }

            if (isSectionHeader(trimmed)) {
                currentSection = trimmed.substring(1, trimmed.length() - 1).trim();
                existing.sections.add(currentSection);
                continue;
            }

            int equalsIndex = trimmed.indexOf('=');
            if (equalsIndex < 0) {
                continue;
            }

            String key = trimmed.substring(0, equalsIndex).trim();
            existing.keysBySection.computeIfAbsent(currentSection, ignored -> new HashSet<>()).add(key);
        }
        return existing;
    }

    private static List<TomlTemplateSection> parseTemplateSections(List<String> lines) {
        List<TomlTemplateSection> sections = new ArrayList<>();
        TomlTemplateSection current = new TomlTemplateSection("");
        sections.add(current);
        List<String> pending = new ArrayList<>();

        for (String line : lines) {
            String trimmed = line.trim();
            if (isSectionHeader(trimmed)) {
                String sectionName = trimmed.substring(1, trimmed.length() - 1).trim();
                current = new TomlTemplateSection(sectionName);
                current.headerComments.addAll(pending);
                pending.clear();
                sections.add(current);
                continue;
            }

            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                pending.add(line);
                continue;
            }

            int equalsIndex = trimmed.indexOf('=');
            if (equalsIndex < 0) {
                pending.add(line);
                continue;
            }

            String key = trimmed.substring(0, equalsIndex).trim();
            List<String> block = new ArrayList<>(pending);
            pending.clear();
            block.add(line);
            current.keyBlocks.putIfAbsent(key, block);
        }

        return sections;
    }

    private static List<String> buildMissingBlocks(ExistingToml existing, List<TomlTemplateSection> sections,
            Long currentConfigVersion) {
        List<String> additions = new ArrayList<>();
        for (TomlTemplateSection section : sections) {
            String sectionName = section.name;
            boolean sectionExists = sectionName.isEmpty() || existing.sections.contains(sectionName);

            if (!sectionExists) {
                appendSectionBlock(additions, section, currentConfigVersion);
                continue;
            }

            Set<String> existingKeys = existing.keysBySection.getOrDefault(sectionName, Set.of());
            List<String> missingBlocks = new ArrayList<>();
            for (Map.Entry<String, List<String>> entry : section.keyBlocks.entrySet()) {
                String key = entry.getKey();
                if (existingKeys.contains(key)) {
                    continue;
                }
                List<String> block = new ArrayList<>(entry.getValue());
                if ("debug".equals(sectionName) && "version".equals(key)) {
                    replaceVersionInBlock(block, currentConfigVersion);
                }
                missingBlocks.addAll(block);
            }

            if (!missingBlocks.isEmpty()) {
                if (!additions.isEmpty() && !additions.get(additions.size() - 1).isBlank()) {
                    additions.add("");
                }
                if (!sectionName.isEmpty()) {
                    additions.add("[" + sectionName + "]");
                }
                additions.addAll(missingBlocks);
            }
        }
        return additions;
    }

    private static void appendSectionBlock(List<String> additions, TomlTemplateSection section,
            Long currentConfigVersion) {
        if (!additions.isEmpty() && !additions.get(additions.size() - 1).isBlank()) {
            additions.add("");
        }
        additions.addAll(section.headerComments);
        if (!section.name.isEmpty()) {
            additions.add("[" + section.name + "]");
        }
        for (Map.Entry<String, List<String>> entry : section.keyBlocks.entrySet()) {
            List<String> block = new ArrayList<>(entry.getValue());
            if ("debug".equals(section.name) && "version".equals(entry.getKey())) {
                replaceVersionInBlock(block, currentConfigVersion);
            }
            additions.addAll(block);
        }
    }

    private static boolean updateDebugVersion(List<String> lines, Long currentConfigVersion) {
        String currentSection = "";
        boolean updated = false;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                continue;
            }
            if (isSectionHeader(trimmed)) {
                currentSection = trimmed.substring(1, trimmed.length() - 1).trim();
                continue;
            }
            int equalsIndex = trimmed.indexOf('=');
            if (equalsIndex < 0) {
                continue;
            }
            String key = trimmed.substring(0, equalsIndex).trim();
            if ("debug".equals(currentSection) && "version".equals(key)) {
                String newLine = replaceTomlValue(line, String.valueOf(currentConfigVersion));
                if (!newLine.equals(line)) {
                    lines.set(i, newLine);
                    updated = true;
                }
            }
        }
        return updated;
    }

    private static void replaceVersionInBlock(List<String> block, Long currentConfigVersion) {
        for (int i = 0; i < block.size(); i++) {
            String line = block.get(i);
            String trimmed = line.trim();
            if (trimmed.startsWith("version") && trimmed.contains("=")) {
                block.set(i, replaceTomlValue(line, String.valueOf(currentConfigVersion)));
                return;
            }
        }
    }

    private static boolean isSectionHeader(String trimmed) {
        return trimmed.startsWith("[") && trimmed.endsWith("]");
    }

    private static String replaceTomlValue(String line, String newValue) {
        int equalsIndex = line.indexOf('=');
        if (equalsIndex < 0) {
            return line;
        }
        String prefix = line.substring(0, equalsIndex + 1);
        String remainder = line.substring(equalsIndex + 1);
        int commentIndex = findInlineCommentIndex(remainder);
        String comment = commentIndex >= 0 ? remainder.substring(commentIndex).trim() : "";
        String suffix = comment.isEmpty() ? "" : " " + comment;
        return prefix + " " + newValue + suffix;
    }

    private static int findInlineCommentIndex(String text) {
        boolean inQuotes = false;
        char quoteChar = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inQuotes) {
                if (c == '\\') {
                    i++;
                } else if (c == quoteChar) {
                    inQuotes = false;
                }
            } else {
                if (c == '"' || c == '\'') {
                    inQuotes = true;
                    quoteChar = c;
                } else if (c == '#') {
                    return i;
                } else if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '/') {
                    return i;
                }
            }
        }
        return -1;
    }

    private static final class ExistingToml {
        private final Set<String> sections = new HashSet<>();
        private final Map<String, Set<String>> keysBySection = new HashMap<>();
    }

    private static final class TomlTemplateSection {
        private final String name;
        private final List<String> headerComments = new ArrayList<>();
        private final LinkedHashMap<String, List<String>> keyBlocks = new LinkedHashMap<>();

        private TomlTemplateSection(String name) {
            this.name = name;
        }
    }

    public static Path getConfigDir() {
        return FabricLoader.getInstance().getConfigDir().resolve("InertiaAntiCheat");
    }

    public static PublicKey retrievePublicKey(PacketByteBuf packetByteBuf) {
        byte[] rawPublicKeyBytes = new byte[packetByteBuf.readableBytes()];
        packetByteBuf.readBytes(rawPublicKeyBytes);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rawPublicKeyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encryptAESBytes(byte[] input, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptAESBytes(byte[] input, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encryptRSABytes(byte[] input, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptRSABytes(byte[] input, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey createAESKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair createRSAPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Something went wrong while generating new key pairs!", e);
        }
    }

    public static byte[] decryptAESRSAEncodedBuf(PacketByteBuf buf, PrivateKey privateKey) {
        int encryptedSecretKeyLength = buf.readInt();
        byte[] encryptedSecretKey = new byte[encryptedSecretKeyLength];
        buf.readBytes(encryptedSecretKey);
        SecretKey secretKey = new SecretKeySpec(InertiaAntiCheat.decryptRSABytes(encryptedSecretKey, privateKey), "AES");

        byte[] encryptedData = new byte[buf.readableBytes()];
        buf.readBytes(encryptedData);
        return InertiaAntiCheat.decryptAESBytes(encryptedData, secretKey);
    }
}
