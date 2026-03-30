package me.noramibu.watchdog;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.bukkit.ChatColor;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

public final class TreasWatchdogPlugin extends JavaPlugin implements Listener {
    private static final long ENDPOINT_NOTICE_THROTTLE_MS = 5000L;
    private static final long PERIODIC_WARNING_TICKS = 20L * 30L;

    private List<DetectionResult> detections = Collections.emptyList();
    private final Map<String, Long> lastEndpointNotice = new ConcurrentHashMap<String, Long>();
    private final Map<String, String> classOwnerCache = new ConcurrentHashMap<String, String>();
    private final List<ConnectionEvent> connectionHistory = Collections.synchronizedList(new ArrayList<ConnectionEvent>());
    private ProxySelector previousProxySelector;
    private boolean networkMonitorEnabled;
    private File pluginsDir;
    private BukkitTask periodicWarningTask;

    @Override
    public void onEnable() {
        pluginsDir = resolvePluginsDirectory();
        networkMonitorEnabled = installNetworkMonitor();
        getServer().getPluginManager().registerEvents(this, this);
        detections = scanPluginsDirectory();
        startPeriodicWarnings();
        if (!detections.isEmpty()) {
            getLogger().warning("[Treas-Watchdog] Startup scan found suspicious artifacts in " + detections.size() + " jar(s).");
            for (DetectionResult result : detections) {
                getLogger().warning("[Treas-Watchdog] " + result.jarName + " -> " + result.toIndicatorText());
            }
        }
    }

    @Override
    public void onDisable() {
        if (periodicWarningTask != null) {
            periodicWarningTask.cancel();
            periodicWarningTask = null;
        }
        if (networkMonitorEnabled && previousProxySelector != null && ProxySelector.getDefault() instanceof MonitoringProxySelector) {
            ProxySelector.setDefault(previousProxySelector);
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (!player.isOp()) {
            return;
        }

        if (detections.isEmpty() && getConnectionHistorySnapshot().isEmpty()) {
            return;
        }
        sendWarningSnapshot(player, null);
    }

    private void startPeriodicWarnings() {
        periodicWarningTask = getServer().getScheduler().runTaskTimer(this, () -> {
            List<Player> recipients = new ArrayList<Player>();
            for (Player online : getServer().getOnlinePlayers()) {
                if (online.isOp()) {
                    recipients.add(online);
                }
            }
            if (recipients.isEmpty()) {
                return;
            }

            if (detections.isEmpty()) {
                List<ConnectionEvent> history = getConnectionHistorySnapshot();
                if (history.isEmpty()) {
                    return;
                }
            }

            for (Player op : recipients) {
                sendWarningSnapshot(op, "Periodic warning (every 30s)");
            }
        }, PERIODIC_WARNING_TICKS, PERIODIC_WARNING_TICKS);
    }

    private void sendWarningSnapshot(Player player, String title) {
        if (title != null && !title.isEmpty()) {
            player.sendMessage(ChatColor.DARK_RED + "[Treas-Watchdog] " + title);
        }
        if (!detections.isEmpty()) {
            player.sendMessage(ChatColor.DARK_RED + "[Treas-Watchdog] Suspicious plugin artifacts detected at startup.");
            for (DetectionResult result : detections) {
                player.sendMessage(ChatColor.RED + "- " + ChatColor.YELLOW + result.jarName + ChatColor.GRAY + " -> " + result.toIndicatorText());
            }
        }

        List<ConnectionEvent> historySnapshot = getConnectionHistorySnapshot();
        if (!historySnapshot.isEmpty()) {
            player.sendMessage(ChatColor.DARK_RED + "[Treas-Watchdog] Leak-pattern connection history (" + historySnapshot.size() + "):");
            for (ConnectionEvent eventItem : historySnapshot) {
                player.sendMessage(ChatColor.RED + "- " + ChatColor.YELLOW + eventItem.source
                        + ChatColor.GRAY + " -> " + eventItem.uri + eventItem.iocSuffix());
            }
        }
    }

    private List<ConnectionEvent> getConnectionHistorySnapshot() {
        synchronized (connectionHistory) {
            return new ArrayList<ConnectionEvent>(connectionHistory);
        }
    }

    private boolean installNetworkMonitor() {
        try {
            previousProxySelector = ProxySelector.getDefault();
            ProxySelector.setDefault(new MonitoringProxySelector(this, previousProxySelector));
            return true;
        } catch (Throwable t) {
            getLogger().warning("[Treas-Watchdog] Could not install outbound monitor: " + t.getClass().getSimpleName() + " " + t.getMessage());
            return false;
        }
    }

    private void onExternalConnectionAttempt(URI uri) {
        if (uri == null) {
            return;
        }

        String host = uri.getHost();
        String scheme = uri.getScheme();
        if (host == null || scheme == null) {
            return;
        }

        String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
        if (!"http".equals(normalizedScheme) && !"https".equals(normalizedScheme)) {
            return;
        }

        if (!isExternalHost(host)) {
            return;
        }

        String fullUrl = String.valueOf(uri).toLowerCase(Locale.ROOT);
        String lowerHost = host.toLowerCase(Locale.ROOT);
        boolean leakHit = fullUrl.contains("leak") || lowerHost.contains("mcleaks.de");
        if (!leakHit) {
            return;
        }

        String source = resolveSourcePluginFromCurrentStack();
        int port = uri.getPort();
        String endpoint = normalizedScheme + "://" + lowerHost + (port > 0 ? ":" + port : "");
        if (!shouldNotifyEndpoint(source + "|" + endpoint)) {
            return;
        }

        boolean mcleaksHit = lowerHost.contains("mcleaks.de");
        ConnectionEvent connectionEvent = new ConnectionEvent(source, String.valueOf(uri), mcleaksHit);
        synchronized (connectionHistory) {
            connectionHistory.add(connectionEvent);
        }

        String message = "[Treas-Watchdog] Leak-pattern outbound URL detected | plugin=" + source
                + " | url=" + connectionEvent.uri + connectionEvent.iocSuffix();
        getLogger().warning(message);

        if (!isEnabled()) {
            return;
        }
        getServer().getScheduler().runTask(this, () -> {
            for (Player player : getServer().getOnlinePlayers()) {
                if (player.isOp()) {
                    player.sendMessage(ChatColor.RED + message);
                }
            }
        });
    }

    private boolean shouldNotifyEndpoint(String endpoint) {
        Long previous = lastEndpointNotice.get(endpoint);
        long now = System.currentTimeMillis();
        if (previous != null && (now - previous.longValue()) < ENDPOINT_NOTICE_THROTTLE_MS) {
            return false;
        }
        lastEndpointNotice.put(endpoint, now);
        return true;
    }

    private boolean isExternalHost(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(lower) || lower.endsWith(".localhost") || "::1".equals(lower)) {
            return false;
        }
        if (lower.startsWith("127.") || lower.startsWith("10.") || lower.startsWith("192.168.") || lower.startsWith("169.254.")) {
            return false;
        }
        if (lower.startsWith("172.")) {
            String[] parts = lower.split("\\.");
            if (parts.length > 1) {
                try {
                    int second = Integer.parseInt(parts[1]);
                    if (second >= 16 && second <= 31) {
                        return false;
                    }
                } catch (NumberFormatException ignored) {
                    // Not a strict IPv4 format; treat as external.
                }
            }
        }
        if (lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
            return false;
        }
        return true;
    }

    private List<DetectionResult> scanPluginsDirectory() {
        if (!pluginsDir.isDirectory()) {
            getLogger().warning("[Treas-Watchdog] Could not locate plugins directory. Checked: " + pluginsDir.getAbsolutePath());
            return Collections.emptyList();
        }

        File[] jarFiles = pluginsDir.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (jarFiles == null || jarFiles.length == 0) {
            return Collections.emptyList();
        }

        List<DetectionResult> findings = new ArrayList<DetectionResult>();
        for (File jarFile : jarFiles) {
            DetectionResult result = inspectJar(jarFile);
            if (result != null) {
                findings.add(result);
            }
        }

        findings.sort(Comparator.comparing(r -> r.jarName.toLowerCase(Locale.ROOT)));
        return Collections.unmodifiableList(findings);
    }

    private DetectionResult inspectJar(File jarFile) {
        boolean hasPluginPatch = false;
        boolean hasRecycleBin = false;
        boolean hasUpdateCoordinatorClass = false;

        try (JarFile jf = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String lowerName = entry.getName().toLowerCase(Locale.ROOT);

                if ("plugin.patch".equals(lowerName) || lowerName.endsWith("/plugin.patch")) {
                    hasPluginPatch = true;
                } else if ("recycle.bin".equals(lowerName) || lowerName.endsWith("/recycle.bin")) {
                    hasRecycleBin = true;
                } else if ("updatecoordinator.class".equals(lowerName) || lowerName.endsWith("/updatecoordinator.class")) {
                    hasUpdateCoordinatorClass = true;
                }

                if (hasPluginPatch && hasRecycleBin && hasUpdateCoordinatorClass) {
                    break;
                }
            }
        } catch (IOException ex) {
            getLogger().warning("[Treas-Watchdog] Failed to inspect " + jarFile.getName() + ": " + ex.getMessage());
            return null;
        }

        if (!hasPluginPatch && !hasRecycleBin && !hasUpdateCoordinatorClass) {
            return null;
        }

        return new DetectionResult(jarFile.getName(), hasPluginPatch, hasRecycleBin, hasUpdateCoordinatorClass);
    }

    private File resolvePluginsDirectory() {
        File result = getDataFolder().getParentFile();
        if (result == null || !result.isDirectory()) {
            result = new File("plugins");
        }
        return result;
    }

    private String resolveSourcePluginFromCurrentStack() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            if (className == null || shouldIgnoreStackClass(className)) {
                continue;
            }
            String source = resolveOwnerForClass(className);
            if (source != null) {
                return source;
            }
        }
        return "unknown";
    }

    private boolean shouldIgnoreStackClass(String className) {
        return className.startsWith("java.")
                || className.startsWith("javax.")
                || className.startsWith("sun.")
                || className.startsWith("jdk.")
                || className.startsWith("org.bukkit.")
                || className.startsWith("org.spigotmc.")
                || className.startsWith("net.minecraft.")
                || className.startsWith("io.papermc.")
                || className.startsWith(getClass().getPackage().getName() + ".");
    }

    private String resolveOwnerForClass(String className) {
        String cached = classOwnerCache.get(className);
        if (cached != null) {
            return cached;
        }

        String byPlugin = resolveByPluginMainPackage(className);
        if (byPlugin != null) {
            classOwnerCache.put(className, byPlugin);
            return byPlugin;
        }

        String byJar = resolveJarByClassEntry(className);
        if (byJar != null) {
            classOwnerCache.put(className, byJar);
            return byJar;
        }

        return null;
    }

    private String resolveByPluginMainPackage(String className) {
        Plugin[] loadedPlugins = getServer().getPluginManager().getPlugins();
        for (Plugin plugin : loadedPlugins) {
            Class<?> mainClass = plugin.getClass();
            String mainName = mainClass.getName();
            if (className.equals(mainName)) {
                return plugin.getName();
            }
            int idx = mainName.lastIndexOf('.');
            if (idx > 0) {
                String pkgPrefix = mainName.substring(0, idx + 1);
                if (className.startsWith(pkgPrefix)) {
                    return plugin.getName();
                }
            }
        }
        return null;
    }

    private String resolveJarByClassEntry(String className) {
        if (!pluginsDir.isDirectory()) {
            return null;
        }
        String classEntry = className.replace('.', '/') + ".class";
        File[] jars = pluginsDir.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (jars == null) {
            return null;
        }
        for (File jar : jars) {
            try (JarFile jarFile = new JarFile(jar)) {
                if (jarFile.getJarEntry(classEntry) != null) {
                    return jar.getName();
                }
            } catch (IOException ignored) {
                // Ignore unreadable jars while resolving source owner.
            }
        }
        return null;
    }

    private static final class DetectionResult {
        private final String jarName;
        private final boolean hasPluginPatch;
        private final boolean hasRecycleBin;
        private final boolean hasUpdateCoordinatorClass;

        private DetectionResult(String jarName, boolean hasPluginPatch, boolean hasRecycleBin, boolean hasUpdateCoordinatorClass) {
            this.jarName = jarName;
            this.hasPluginPatch = hasPluginPatch;
            this.hasRecycleBin = hasRecycleBin;
            this.hasUpdateCoordinatorClass = hasUpdateCoordinatorClass;
        }

        private String toIndicatorText() {
            List<String> markers = new ArrayList<String>(3);
            if (hasPluginPatch) {
                markers.add("plugin.patch");
            }
            if (hasRecycleBin) {
                markers.add("recycle.bin");
            }
            if (hasUpdateCoordinatorClass) {
                markers.add("UpdateCoordinator.class");
            }
            return String.join(", ", markers);
        }
    }

    private static final class ConnectionEvent {
        private final String source;
        private final String uri;
        private final boolean mcleaks;

        private ConnectionEvent(String source, String uri, boolean mcleaks) {
            this.source = source;
            this.uri = uri;
            this.mcleaks = mcleaks;
        }

        private String iocSuffix() {
            return mcleaks ? " [IOC: mcleaks.de]" : " [IOC: contains 'leak']";
        }
    }

    private static final class MonitoringProxySelector extends ProxySelector {
        private final TreasWatchdogPlugin plugin;
        private final ProxySelector delegate;

        private MonitoringProxySelector(TreasWatchdogPlugin plugin, ProxySelector delegate) {
            this.plugin = plugin;
            this.delegate = delegate;
        }

        @Override
        public List<Proxy> select(URI uri) {
            plugin.onExternalConnectionAttempt(uri);
            if (delegate == null) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            List<Proxy> selected = delegate.select(uri);
            if (selected == null || selected.isEmpty()) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            return selected;
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            if (delegate != null) {
                delegate.connectFailed(uri, sa, ioe);
            }
        }
    }
}
