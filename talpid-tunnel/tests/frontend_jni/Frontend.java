package net.mullvad.talpid.fixture;

/** JVM-only model of the service's fallible ownership boundary, not an Android hook. */
public final class Frontend {
    public boolean owned;
    public boolean failOpen;
    public boolean failUnregister;
    public int failBind;

    public Object openLocalFrontend(long generation, String[] routes) {
        if (owned) throw new IllegalStateException("frontend overlap");
        owned = true;
        if (failOpen) {
            unregisterNetworkCallback();
            owned = false;
            throw new IllegalStateException("startup failed");
        }
        return new Object();
    }

    public boolean bindLocalFrontend(long generation, String name) {
        if (failBind == 1) throw new SecurityException("interface bind failed");
        if (failBind == 2) throw new BrokenDiagnostic();
        return owned;
    }

    public void finishLocalFrontend() {
        if (owned) {
            unregisterNetworkCallback();
            owned = false;
        }
    }

    private void unregisterNetworkCallback() {
        if (failUnregister) throw new SecurityException("unregister capture callback");
    }

    private static final class BrokenDiagnostic extends RuntimeException {
        @Override public String toString() { throw new IllegalStateException("diagnostic failed"); }
    }
}
