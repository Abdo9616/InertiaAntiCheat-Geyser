package com.diffusehyperion.inertiaanticheat.server;

import com.diffusehyperion.inertiaanticheat.common.interfaces.UpgradedServerCommonNetworkHandler;
import com.diffusehyperion.inertiaanticheat.common.interfaces.UpgradedServerLoginNetworkHandler;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.minecraft.network.ClientConnection;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import net.minecraft.server.network.ServerPlayNetworkHandler;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static com.diffusehyperion.inertiaanticheat.server.InertiaAntiCheatServer.debugInfo;
import static com.diffusehyperion.inertiaanticheat.server.InertiaAntiCheatServer.debugLine;

final class GeyserBypassTracker {
    private static final Set<ClientConnection> PENDING_CONNECTIONS = ConcurrentHashMap.newKeySet();

    private GeyserBypassTracker() {
    }

    static void register() {
        ServerPlayConnectionEvents.JOIN.register(GeyserBypassTracker::handleJoin);
        ServerPlayConnectionEvents.DISCONNECT.register(GeyserBypassTracker::handleDisconnect);
        ServerLoginConnectionEvents.DISCONNECT.register(GeyserBypassTracker::handleLoginDisconnect);
    }

    static boolean markPending(ClientConnection connection) {
        if (connection == null) {
            return false;
        }
        return PENDING_CONNECTIONS.add(connection);
    }

    private static void handleJoin(ServerPlayNetworkHandler handler, net.fabricmc.fabric.api.networking.v1.PacketSender sender, MinecraftServer server) {
        if (!allowGeyserClients()) {
            return;
        }
        ClientConnection connection = extractConnection(handler);
        if (connection == null || !PENDING_CONNECTIONS.remove(connection)) {
            return;
        }
        ServerPlayerEntity player = handler.player;
        FloodgateBridge bridge = FloodgateBridge.get();
        boolean floodgate = bridge.isFloodgatePlayer(player.getUuid());
        if (!floodgate && !bridge.isAvailable()) {
            debugInfo(player.getName().getString() + " joined while pending geyser validation, but Floodgate API is unavailable");
            disconnectVanilla(player);
            return;
        }

        if (!floodgate) {
            debugInfo(player.getName().getString() + " was pending geyser validation but is not a Floodgate player");
            disconnectVanilla(player);
            return;
        }

        debugInfo(player.getName().getString() + " confirmed as Floodgate player after login");
        debugLine();
    }

    private static void handleDisconnect(ServerPlayNetworkHandler handler, MinecraftServer server) {
        ClientConnection connection = extractConnection(handler);
        if (connection != null) {
            PENDING_CONNECTIONS.remove(connection);
        }
    }

    private static void handleLoginDisconnect(ServerLoginNetworkHandler handler, MinecraftServer server) {
        if (!allowGeyserClients()) {
            return;
        }
        UpgradedServerLoginNetworkHandler upgraded = (UpgradedServerLoginNetworkHandler) handler;
        ClientConnection connection = upgraded.inertiaAntiCheat$getConnection();
        if (connection != null) {
            PENDING_CONNECTIONS.remove(connection);
        }
    }

    private static boolean allowGeyserClients() {
        return InertiaAntiCheatServer.serverConfig != null
                && InertiaAntiCheatServer.serverConfig.getBoolean("geyser.allow_geyser_clients", false);
    }

    private static void disconnectVanilla(ServerPlayerEntity player) {
        player.networkHandler.disconnect(Text.of(
                InertiaAntiCheatServer.serverConfig.getString("validation.vanillaKickMessage")
        ));
    }

    private static ClientConnection extractConnection(ServerPlayNetworkHandler handler) {
        if (!(handler instanceof UpgradedServerCommonNetworkHandler upgraded)) {
            return null;
        }
        return upgraded.inertiaAntiCheat$getConnection();
    }
}
