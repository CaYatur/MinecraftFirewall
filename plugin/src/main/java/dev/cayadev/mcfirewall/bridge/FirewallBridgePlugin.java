package dev.cayadev.mcfirewall.bridge;

import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * The optional server-side half of MinecraftFirewall.
 *
 * <p>Everything the firewall does works without this. What it cannot do from outside the server is
 * stop a creeper: a player waiting at the login prompt is genuinely standing in the world, and only
 * the server decides their health. This plugin is the part that is inside, so it can.
 *
 * <p>It does three things and deliberately nothing else:
 *
 * <ul>
 *   <li>Makes a held player untouchable, from any source, and stops them starving.</li>
 *   <li>Keeps them where they are, so nothing can push or pull them while they read the prompt.</li>
 *   <li>Declares {@code /login}, {@code /register} and {@code /premium} so the client renders them
 *       as real commands and {@code /help} lists them. The firewall answers all three before the
 *       server ever sees them; the executors exist only so the client knows they are real.</li>
 * </ul>
 *
 * <p><b>It never decides anything.</b> Who is held, and for how long, is the firewall's judgement
 * alone. This plugin holds whoever it is told to hold and releases them when told. That is the whole
 * of its authority, and it is deliberately small: a plugin that made its own decisions would be a
 * second implementation of the rules, free to disagree with the first.
 *
 * <p><b>On trust.</b> Instructions arrive as a plugin message on the player's own connection, and a
 * message therefore cannot name anybody: the player it applies to is the player it arrived on, and
 * there is no field to say otherwise. That is not an accident of the format, it is the reason for
 * it — a protocol that could address another player would let anyone freeze anyone. The firewall
 * separately refuses to forward anything a client sends on this channel, so the only thing that can
 * reach the code below is the firewall itself.
 *
 * <p>Compiled against the 1.8 API using only calls that have existed since then, so one jar runs on
 * every server this firewall supports and on versions that do not exist yet.
 */
public final class FirewallBridgePlugin extends JavaPlugin implements Listener, PluginMessageListener {

    /** Must match Bridge/PluginBridge.cs on the firewall side. */
    private static final String CHANNEL = "mcfirewall:auth";

    private static final byte PROTOCOL_VERSION = 1;

    // 0 is reserved for an announce the plugin deliberately does not send. It would travel to the
    // client, which has no use for it and would log an unknown channel; the server console already
    // says on startup that this plugin loaded, which is where an administrator looks anyway.
    private static final byte OPCODE_HOLD = 1;
    private static final byte OPCODE_RELEASE = 2;

    /**
     * Players the firewall has asked us to hold.
     *
     * <p>Synchronised because plugin messages arrive on a different thread from the events below on
     * some server builds. A set that is read every time anybody moves is not a good place to find
     * out the hard way which thread you are on.
     */
    private final Set<UUID> held = Collections.synchronizedSet(new HashSet<UUID>());

    @Override
    public void onEnable() {
        getServer().getMessenger().registerIncomingPluginChannel(this, CHANNEL, this);
        getServer().getPluginManager().registerEvents(this, this);

        getLogger().info("Ready. Players held at the login prompt are protected from damage and kept in place.");
        getLogger().info("This plugin never decides who is held. MinecraftFirewall decides, and tells it.");
    }

    @Override
    public void onDisable() {
        // Nobody stays frozen because the plugin stopped. Whatever is in here was temporary state
        // owned by something that is no longer running, and leaving it applied would strand people.
        held.clear();
    }

    // ---- what the firewall tells us -----------------------------------------------------------

    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!CHANNEL.equals(channel) || message.length < 2 || message[0] != PROTOCOL_VERSION) {
            return;
        }

        // The player this applies to is the player it arrived on. There is no field for a name, so
        // there is nothing to validate and no way to aim this at somebody else.
        switch (message[1]) {
            case OPCODE_HOLD:
                hold(player);
                break;
            case OPCODE_RELEASE:
                release(player);
                break;
            default:
                break;
        }
    }

    private void hold(Player player) {
        if (!held.add(player.getUniqueId())) {
            return; // already held; being told again is normal, acting twice is not
        }

        // Guarded separately. Blindness is the one call here that later versions reorganised, and a
        // server where it fails must still get the protection that actually matters.
        try {
            player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 0, false, false));
        } catch (Throwable ignored) {
            // A darkened screen is a nicety. Not being killed is not.
        }
    }

    private void release(Player player) {
        if (!held.remove(player.getUniqueId())) {
            return;
        }

        try {
            player.removePotionEffect(PotionEffectType.BLINDNESS);
        } catch (Throwable ignored) {
        }
    }

    private boolean isHeld(Player player) {
        return held.contains(player.getUniqueId());
    }

    // ---- what being held means ----------------------------------------------------------------

    /**
     * The reason this plugin exists.
     *
     * <p>Cancelling the damage event rather than setting invulnerability is deliberate: it covers
     * every source, including the ones that are not entities at all — falling, drowning, the void,
     * fire — and it works on every server version rather than only newer ones.
     *
     * <p>Highest priority, and cancelled events are still seen, so nothing else can undo it. A held
     * player has not proved who they are yet; nothing should be allowed to kill them for that.
     */
    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = false)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player && isHeld((Player) event.getEntity())) {
            event.setCancelled(true);
        }
    }

    /** Starving to death at the login prompt is the same problem wearing a different hat. */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onHunger(FoodLevelChangeEvent event) {
        if (event.getEntity() instanceof Player && isHeld((Player) event.getEntity())) {
            event.setCancelled(true);
        }
    }

    /**
     * Keeps a held player where they are.
     *
     * <p>Only actual movement is refused — looking around is left alone, because stopping somebody
     * turning their head reads as a frozen game rather than as a rule. The firewall already refuses
     * their movement packets; this stops the world moving them.
     */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onMove(PlayerMoveEvent event) {
        if (!isHeld(event.getPlayer())) {
            return;
        }

        Location from = event.getFrom();
        Location to = event.getTo();

        if (to == null) {
            return;
        }

        if (from.getBlockX() != to.getBlockX()
                || from.getBlockY() != to.getBlockY()
                || from.getBlockZ() != to.getBlockZ()) {
            event.setCancelled(true);
        }
    }

    // ---- the commands ---------------------------------------------------------------------------

    /**
     * Does nothing, on purpose.
     *
     * <p>These commands are declared in plugin.yml so the client knows they exist: an undeclared
     * command is painted red in the chat box and is missing from {@code /help}, which made a working
     * login look broken and left players with nowhere to find out how to claim their name.
     *
     * <p>Declaring them is the entire job. The firewall intercepts all three before the server sees
     * them, so nothing ever reaches this method during a login. If something does, the player typed
     * one outside a login, and the right answer is still to say nothing and let it pass quietly.
     *
     * <p>An empty executor looks like an oversight. It is not: implementing anything here would be a
     * second copy of the login rules, on the far side of the boundary that enforces them.
     */
    @Override
    public boolean onCommand(org.bukkit.command.CommandSender sender, org.bukkit.command.Command command,
                             String label, String[] args) {
        return true;
    }

    /**
     * Somebody who disconnects while held is not held any more. Without this the set grows for the
     * lifetime of the server, one entry per player who ever gave up at the prompt.
     */
    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        held.remove(event.getPlayer().getUniqueId());
    }
}
