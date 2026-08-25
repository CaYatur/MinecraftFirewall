package dev.cayadev.mcfirewall.bridge;

import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.player.PlayerJoinEvent;
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

    /**
     * How long the darkened screen lasts before it expires on its own, and how often it is renewed
     * while somebody is still held.
     *
     * <p>Bounded, and that is the entire point. The first version of this used
     * {@code Integer.MAX_VALUE} — effectively forever — and cleared it only when the firewall said to
     * release. A player kicked while held (asking to lock their name does exactly that) quit without
     * ever being released, and the effect was written into their saved data. They came back blind,
     * permanently, with nothing left running that knew to undo it.
     *
     * <p>So the effect now outlives nothing: it is tied to this plugin's own set of held players,
     * renewed by this plugin's own task while they are in it, and gone within twenty seconds of them
     * leaving it whatever happens to the connection. A temporary effect must not be able to become a
     * permanent one.
     */
    private static final int BLINDNESS_TICKS = 20 * 20;
    private static final long RENEW_EVERY_TICKS = 20 * 10;

    /** Longer than any potion a player could be carrying, and shorter than the broken effect this
     * used to leave behind. Used to recognise that leftover and clear it. */
    private static final int IMPOSSIBLE_DURATION_TICKS = 20 * 60 * 60;

    @Override
    public void onEnable() {
        getServer().getMessenger().registerIncomingPluginChannel(this, CHANNEL, this);
        getServer().getPluginManager().registerEvents(this, this);

        // Renews the darkened screen for everybody still held. The effect is deliberately short-lived,
        // so this task is what keeps it going — which means it stops the moment somebody leaves the
        // set, or the moment this plugin stops, without anything having to remember to undo it.
        getServer().getScheduler().runTaskTimer(this, new Runnable() {
            @Override
            public void run() {
                renewHeldPlayers();
            }
        }, RENEW_EVERY_TICKS, RENEW_EVERY_TICKS);

        getLogger().info("Ready. Players held at the login prompt are protected from damage and kept in place.");
        getLogger().info("This plugin never decides who is held. MinecraftFirewall decides, and tells it.");
    }

    @Override
    public void onDisable() {
        // Nobody stays frozen, or blind, because the plugin stopped. Whatever was in here was
        // temporary state owned by something that is no longer running, and leaving it applied would
        // strand people.
        for (UUID id : snapshotHeld()) {
            Player player = getServer().getPlayer(id);
            if (player != null) {
                clearBlindness(player);
            }
        }

        held.clear();
    }

    private UUID[] snapshotHeld() {
        synchronized (held) {
            return held.toArray(new UUID[0]);
        }
    }

    private void renewHeldPlayers() {
        for (UUID id : snapshotHeld()) {
            Player player = getServer().getPlayer(id);
            if (player != null && player.isOnline()) {
                applyBlindness(player);
            }
        }
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

        applyBlindness(player);
    }

    /**
     * Darkens the screen for a short while. Renewed by the task above for as long as the player is
     * held, so it follows the set exactly and cannot outlast it.
     *
     * <p>Guarded separately from everything else: blindness is the one call here that later versions
     * reorganised, and a server where it fails must still get the protection that actually matters.
     */
    private void applyBlindness(Player player) {
        try {
            player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, BLINDNESS_TICKS, 0, false, false), true);
        } catch (Throwable ignored) {
            // A darkened screen is a nicety. Not being killed is not.
        }
    }

    private void clearBlindness(Player player) {
        try {
            player.removePotionEffect(PotionEffectType.BLINDNESS);
        } catch (Throwable ignored) {
        }
    }

    private void release(Player player) {
        if (!held.remove(player.getUniqueId())) {
            return;
        }

        clearBlindness(player);
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
        if (held.remove(event.getPlayer().getUniqueId())) {
            // Cleared here as well as by expiry, because a player who is kicked while held — which is
            // exactly what asking to lock your name does — is never released by the firewall. Without
            // this the effect went into their saved data and came back with them.
            clearBlindness(event.getPlayer());
        }
    }

    /**
     * Clears a darkened screen this plugin should never have left behind.
     *
     * <p>An earlier version applied blindness that effectively never expired, and a player kicked
     * while held kept it in their saved data forever. Nothing that runs today can produce a blindness
     * that long, and no potion in the game grants one either — so an hour is a length only that bug
     * could have caused, which makes it safe to undo without touching an effect somebody meant to
     * have.
     */
    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();

        try {
            for (PotionEffect effect : player.getActivePotionEffects()) {
                if (PotionEffectType.BLINDNESS.equals(effect.getType())
                        && effect.getDuration() > IMPOSSIBLE_DURATION_TICKS) {
                    clearBlindness(player);
                    getLogger().info("Cleared a stuck blindness effect from " + player.getName()
                            + " that an earlier version of this plugin left behind.");
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
    }
}
