package com.diffusehyperion.inertiaanticheat.mixins.server;

import com.diffusehyperion.inertiaanticheat.common.interfaces.UpgradedServerCommonNetworkHandler;
import net.minecraft.network.ClientConnection;
import net.minecraft.server.network.ServerCommonNetworkHandler;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;

@Mixin(ServerCommonNetworkHandler.class)
public abstract class ServerCommonNetworkHandlerMixin implements UpgradedServerCommonNetworkHandler {
    @Shadow @Final
    ClientConnection connection;

    @Override
    public ClientConnection inertiaAntiCheat$getConnection() {
        return this.connection;
    }
}
