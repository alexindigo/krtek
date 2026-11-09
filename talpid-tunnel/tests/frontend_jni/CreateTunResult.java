package net.mullvad.talpid.model;

/** JVM-only result classes with the real production signatures. */
public class CreateTunResult {
    public static final class Success extends CreateTunResult {
        private final int fd;
        private final boolean fail;
        public Success(int fd, boolean fail) { this.fd = fd; this.fail = fail; }
        public int getTunFd() {
            if (fail) throw new IllegalStateException("fd getter");
            return fd;
        }
    }
    public static final class EstablishError extends CreateTunResult {}
    public static final class OtherLegacyAlwaysOnVpn extends CreateTunResult {}
    public static final class NotPrepared extends CreateTunResult {}
    public static final class OtherAlwaysOnApp extends CreateTunResult {
        public String getAppName() { return "other.vpn"; }
    }
}
