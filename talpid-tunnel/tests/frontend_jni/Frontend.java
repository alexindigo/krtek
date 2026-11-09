package net.mullvad.talpid.fixture;

import net.mullvad.talpid.model.CaptureHandoverResult;
import net.mullvad.talpid.model.CreateTunResult;

/** JVM-only model of the service's fallible ownership boundary, not an Android hook. */
public final class Frontend {
    public boolean owned;
    public boolean failOpen;
    public boolean failUnregister;
    public int failBind;
    public boolean failHandover;
    public int pendingFd = -1;
    public int mode;
    public int transfers;
    private static native void closeFd(int fd);

    public CaptureHandoverResult conversionHandover(int fd, int mode) {
        this.pendingFd = fd;
        this.mode = mode;
        owned = true;
        if (mode == 4) throw new IllegalStateException("open acknowledgement");
        CreateTunResult result = mode == 8 ? new CreateTunResult() :
            new CreateTunResult.Success(mode == 6 ? fd + 1 : mode == 7 ? -1 : fd, mode == 2);
        return new CaptureHandoverResult(result, mode);
    }

    public int takeLocalFrontendDescriptor(long generation) {
        if (mode == 5) throw new IllegalStateException("before detach");
        if (generation != 12 || pendingFd < 0) throw new IllegalStateException("stale take");
        int fd = pendingFd;
        pendingFd = -1;
        transfers++;
        return fd;
    }

    public Object handoverLocalFrontend(long predecessor, long generation, String[] routes) {
        if (failHandover) throw new SecurityException("handover local acknowledgement");
        return new Object();
    }

    public Object handoverSecuredFrontend(long predecessor, long generation, Object config) {
        if (failHandover) throw new SecurityException("handover secured acknowledgement");
        return new Object();
    }

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

    public void finishLocalFrontend(long generation) {
        if (owned) {
            if (pendingFd >= 0) {
                closeFd(pendingFd);
                pendingFd = -1;
            }
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
