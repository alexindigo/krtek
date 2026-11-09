package net.mullvad.talpid.model;

/** JVM-only faultable result; no production test hook. */
public final class CaptureHandoverResult {
    private final CreateTunResult result;
    private final int mode;
    public CaptureHandoverResult(CreateTunResult result, int mode) {
        this.result = result;
        this.mode = mode;
    }
    public CreateTunResult getResult() {
        if (mode == 1) throw new IllegalStateException("result getter");
        return result;
    }
    public boolean getPredecessorRetained() {
        if (mode == 3) throw new IllegalStateException("retention getter");
        return false;
    }
}
