package net.mullvad.mullvadvpn.talpid;

import android.app.Service;
import android.content.Intent;
import android.content.pm.InstrumentationInfo;
import android.content.pm.PackageManager;
import android.net.InetAddresses;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.security.SecureRandom;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/** Ordinary, unbound networking in the neutral test APK's own process and UID.
 *
 * <p>This process has no target-app classpath: use only platform and Java runtime APIs.
 */
public final class LocalNetworkConsumerService extends Service {
  public static String[] requiredPermissions() {
    return new String[] {
      "android.permission.INTERNET",
      "android.permission.ACCESS_NETWORK_STATE",
      "android.permission.ACCESS_LOCAL_NETWORK"
    };
  }

  private static final Pattern NONCE = Pattern.compile("krtek-m3-[A-Za-z0-9-]{1,64}");
  private final ThreadPoolExecutor worker =
      new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(8));
  private final ThreadPoolExecutor sessionCommands =
      new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(8));
  private final Handler main = new Handler(Looper.getMainLooper());
  private boolean expired;
  private volatile ProbeResources activeProbe;
  private volatile Session session;
  private String allowedCaller;
  private final Messenger messenger =
      new Messenger(
          new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message message) {
              String[] packages = getPackageManager().getPackagesForUid(message.sendingUid);
              if (message.replyTo == null
                  || packages == null
                  || !Arrays.asList(packages).contains(allowedCaller)
                  || getPackageManager().checkSignatures(message.sendingUid, Process.myUid())
                      != PackageManager.SIGNATURE_MATCH) {
                return;
              }
              submit(new Bundle(message.getData()), message.replyTo);
            }
          });

  @Override
  public void onCreate() {
    super.onCreate();
    try {
      // Read this APK's own instrumentation record, not a target-filtered query.
      InstrumentationInfo[] records =
          getPackageManager()
              .getPackageInfo(getPackageName(), PackageManager.GET_INSTRUMENTATION)
              .instrumentation;
      if (records == null
          || records.length != 1
          || !getPackageName().equals(records[0].packageName)
          || records[0].targetPackage == null
          || getPackageName().equals(records[0].targetPackage)) {
        throw new IllegalStateException("Expected one distinct target in own instrumentation record");
      }
      allowedCaller = records[0].targetPackage;
    } catch (PackageManager.NameNotFoundException error) {
      throw new IllegalStateException("Own instrumentation record missing", error);
    }
  }

  @Override
  public IBinder onBind(Intent intent) {
    return messenger.getBinder();
  }

  @Override
  public boolean onUnbind(Intent intent) {
    Session running = session;
    if (running != null) running.stop("caller-unbound");
    return false;
  }

  @Override
  public void onDestroy() {
    expired = true;
    main.removeCallbacksAndMessages(null);
    worker.shutdownNow();
    sessionCommands.shutdownNow();
    Session running = session;
    if (running != null) running.stop("service-destroyed");
    ProbeResources active = activeProbe;
    if (active != null) active.close();
    super.onDestroy();
  }

  private static Bundle outcome(String value) {
    Bundle result = new Bundle();
    result.putString("outcome", value);
    return result;
  }

  private void submit(Bundle command, Messenger reply) {
    if (expired) {
      send(reply, command, outcome("deadline"));
      return;
    }
    AtomicBoolean completed = new AtomicBoolean(false);
    AtomicReference<ProbeResources> ownedResources = new AtomicReference<>();
    FutureTask<Void> task =
        new FutureTask<>(
            () -> {
               Bundle result = execute(command, ownedResources);
              if (completed.compareAndSet(false, true)) send(reply, command, result);
              return null;
            });
    Runnable deadline =
        () -> {
          if (completed.compareAndSet(false, true)) {
             task.cancel(true);
             ProbeResources active = ownedResources.get();
            if (active != null) active.close();
            send(reply, command, outcome("deadline"));
          }
        };
    try {
      String transport = command.getString("transport");
      (transport != null && transport.startsWith("session-") ? sessionCommands : worker).execute(task);
      main.postDelayed(deadline,
          ("lookup".equals(transport) || "exit-check".equals(transport) || "icmp-check".equals(transport))
              ? 30000L : 12000L);
    } catch (RejectedExecutionException ignored) {
      completed.set(true);
      send(reply, command, outcome("capacity"));
    }
  }

  private Bundle execute(Bundle command, AtomicReference<ProbeResources> ownedResources) {
    String transport = command.getString("transport");
    if (transport != null && transport.startsWith("session-")) return sessionCommand(command);
    if ("identity".equals(transport)) {
      Bundle result = outcome("identity");
      result.putString("application_class", getApplication().getClass().getName());
      return result;
    }
    if ("lookup".equals(transport)) return lookup(command);
    if ("exit-check".equals(transport) || "icmp-check".equals(transport)) {
      if (command.size() != 2 || !command.containsKey("request_id")) return outcome("invalid");
      ProbeResources resources = new ProbeResources();
      ownedResources.set(resources);
      activeProbe = resources;
      try {
        if (Thread.currentThread().isInterrupted()) return outcome("deadline");
        return "exit-check".equals(transport) ? exitCheck(resources) : icmpCheck(resources);
      } finally {
        resources.close();
        activeProbe = null;
      }
    }
    String destination = command.getString("destination");
    String nonce = command.getString("nonce");
    int port = command.getInt("port");
    int timeout = command.getInt("timeout_ms");
    if (!("tcp".equals(transport) || "udp".equals(transport) || "tcp-connect".equals(transport))
        || destination == null
        || nonce == null
        || !NONCE.matcher(nonce).matches()
        || !(port == 18080 || port == 18081 || port == 443)
        || timeout < 1
        || timeout > 5000
        || !InetAddresses.isNumericAddress(destination)) {
      return outcome("invalid");
    }
    SocketReport report = new SocketReport();
    try {
      InetAddress address = InetAddresses.parseNumericAddress(destination);
      if ("tcp-connect".equals(transport)) {
        tcp(address, port, null, timeout, report);
        Bundle result = outcome("connected");
        result.putString("socket_report", report.snapshot());
        return result;
      }
      byte[] payload = nonce.getBytes(StandardCharsets.US_ASCII);
      byte[] bytes =
          "tcp".equals(transport)
              ? tcp(address, port, payload, timeout, report)
              : udp(address, port, payload, timeout, report);
      Bundle result = outcome("reply");
      result.putByteArray("reply", bytes);
      result.putString("socket_report", report.snapshot());
      return result;
    } catch (Exception error) {
      Bundle result = outcome("failed");
      result.putString("error_class", error.getClass().getName());
      result.putString("socket_report", report.snapshot());
      return result;
    }
  }

  private Bundle sessionCommand(Bundle command) {
    String operation = command.getString("transport");
    if ("session-start".equals(operation)) {
      String destination = command.getString("destination");
      int duration = command.getInt("duration_ms");
      if (command.size() != 4 || destination == null || !InetAddresses.isNumericAddress(destination)
          || duration < 2000 || duration > 480000) return outcome("invalid");
      if (session != null && session.stopped == 0) return outcome("session-exists");
      Session created = new Session(InetAddresses.parseNumericAddress(destination), duration);
      session = created;
      created.start();
      return created.snapshot(0, 0);
    }
    Session running = session;
    if (running == null || !running.id.equals(command.getString("session_id"))) return outcome("invalid");
    if ("session-stop".equals(operation) && command.size() == 3) {
      running.stop("requested");
      return running.snapshot(0, 0);
    }
    if ("session-snapshot".equals(operation) && command.size() == 5)
      return running.snapshot(command.getInt("local_cursor"), command.getInt("public_cursor"));
    if ("session-burst".equals(operation) && command.size() == 3) {
      running.burst.set(true);
      return running.snapshot(0, 0);
    }
    return outcome("invalid");
  }

  /** One lifetime, no reopen. All timestamps use Android CLOCK_BOOTTIME. */
  private static final class Session {
    final String id = UUID.randomUUID().toString().replace("-", "").substring(0, 29);
    final InetAddress destination;
    final long created = SystemClock.elapsedRealtimeNanos();
    volatile long started;
    final CountDownLatch socketsReady = new CountDownLatch(2);
    final long end;
    final ArrayList<JSONObject> local = new ArrayList<>();
    final ArrayList<JSONObject> publicLedger = new ArrayList<>();
    final Set<Socket> publicSockets = new HashSet<>();
    final AtomicBoolean burst = new AtomicBoolean();
    final ArrayBlockingQueue<SessionFrame> tcpPending = new ArrayBlockingQueue<>(21);
    final ConcurrentHashMap<String, SessionFrame> udpPending = new ConcurrentHashMap<>();
    final ScheduledThreadPoolExecutor watchdog = new ScheduledThreadPoolExecutor(2);
    final ThreadPoolExecutor publicWorkers = new ThreadPoolExecutor(
        3, 3, 0, TimeUnit.SECONDS, new SynchronousQueue<>());
    final Socket tcp = new Socket();
    DatagramSocket udp;
    Thread tcpPump, udpPump, publicPump, tcpReader, udpReader;
    volatile boolean stopping;
    String failure;
    String stopReason;
    long stopRequested;
    long stopped;
    int tcpFrames;
    final JSONObject tcpIdentity = new JSONObject();
    final JSONObject udpIdentity = new JSONObject();

    Session(InetAddress destination, int duration) {
      this.destination = destination;
      end = created + duration * 1000000L;
      watchdog.setRemoveOnCancelPolicy(true);
    }

    void start() {
      tcpPump = new Thread(() -> pump(true), "krtek-session-tcp");
      udpPump = new Thread(() -> pump(false), "krtek-session-udp");
      publicPump = new Thread(this::publicPump, "krtek-session-public");
      tcpPump.start(); udpPump.start(); publicPump.start();
      watchdog.schedule(() -> stop("session-deadline"),
          Math.max(1, end - SystemClock.elapsedRealtimeNanos()), TimeUnit.NANOSECONDS);
    }

    synchronized void fail(String reason) {
      if (failure == null) failure = reason;
      stopping = true;
      closeSockets();
    }

    synchronized void closeSockets() {
      try { tcp.close(); } catch (IOException error) { if (failure == null) failure = "tcp-close"; }
      if (udp != null) udp.close();
      for (Socket socket : publicSockets) {
        try { socket.close(); } catch (IOException error) { if (failure == null) failure = "public-close"; }
      }
      SessionFrame pending;
      while ((pending = tcpPending.poll()) != null) cancelFrame(pending);
      for (SessionFrame frame : udpPending.values()) cancelFrame(frame);
      udpPending.clear();
    }

    private void cancelFrame(SessionFrame frame) {
      put(frame.record, "outcome", "cancelled");
      put(frame.record, "cancel_ns", SystemClock.elapsedRealtimeNanos());
      put(frame.record, "error_kind", "owner-closed");
      frame.guard.cancel(false);
    }

    private synchronized void expireUdp(String nonce) {
      SessionFrame frame = udpPending.remove(nonce);
      if (frame == null) return;
      // Preserve the original five-second expiry, without closing the owner and
      // cancelling unrelated exchanges. The log-correlated auditor decides whether
      // this loss is allowed; the consumer cannot infer a rebuild from tunnel state.
      put(frame.record, "outcome", "udp-reply-missing");
      put(frame.record, "deadline_ns", frame.deadline);
      put(frame.record, "expired_ns", SystemClock.elapsedRealtimeNanos());
    }

    void stop(String reason) {
      boolean graceful = "requested".equals(reason);
      synchronized (this) {
        if (stopped != 0) return;
        if (stopReason == null) stopReason = reason;
        stopRequested = SystemClock.elapsedRealtimeNanos();
        if (!"requested".equals(reason) && failure == null) failure = reason;
        stopping = true;
        if (!graceful) closeSockets();
      }
      long joinDeadline = SystemClock.elapsedRealtimeNanos() + 6000000000L;
      // Stop every producer before closing the admission/drain side it owns.
      joinPumps(graceful, joinDeadline, tcpPump, udpPump, publicPump);
      // Readers can be installed during producer startup; sample them only after
      // joining their producers, not in the same pre-join array snapshot.
      joinPumps(graceful, joinDeadline, tcpReader, udpReader);
      publicWorkers.shutdown();
      try { if (!publicWorkers.awaitTermination(Math.max(1, joinDeadline - SystemClock.elapsedRealtimeNanos()),
          TimeUnit.NANOSECONDS)) fail("public-join"); }
      catch (InterruptedException error) { Thread.currentThread().interrupt(); fail("public-join-interrupted"); }
      watchdog.shutdownNow();
      publicWorkers.shutdownNow();
      synchronized (this) { closeSockets(); stopped = SystemClock.elapsedRealtimeNanos(); }
    }

    private void joinPumps(boolean graceful, long joinDeadline, Thread... threads) {
      for (Thread thread : threads) {
        if (thread != null && thread != Thread.currentThread()) {
          if (!graceful) thread.interrupt();
          try { thread.join(Math.max(1, (joinDeadline - SystemClock.elapsedRealtimeNanos()) / 1000000L)); }
          catch (InterruptedException error) { Thread.currentThread().interrupt(); fail("stop-interrupted"); }
          if (thread.isAlive()) fail("pump-join");
        }
      }
    }

    private static void put(JSONObject object, String key, Object value) {
      SocketReport.put(object, key, value);
    }

    synchronized JSONObject tick(boolean ordinary, String transport, int index, long scheduled) {
      ArrayList<JSONObject> ledger = ordinary ? publicLedger : local;
      if (ledger.size() == (ordinary ? 1024 : 4096)) { fail("ledger-overflow"); return null; }
      JSONObject record = new JSONObject();
      put(record, "transport", transport); put(record, "tick", index);
      put(record, "scheduled_ns", scheduled); put(record, "session_id", id);
      put(record, "uid", Process.myUid()); put(record, "pid", Process.myPid());
      put(record, "outcome", "pending");
      ledger.add(record);
      return record;
    }

    synchronized void update(JSONObject record, String key, Object value) { put(record, key, value); }

    private void waitUntil(long scheduled) throws InterruptedException {
      long remaining;
      while (!stopping && (remaining = scheduled - SystemClock.elapsedRealtimeNanos()) > 0)
        TimeUnit.NANOSECONDS.sleep(remaining);
    }

    private int remaining(long deadline) throws SocketTimeoutException {
      long remaining = deadline - SystemClock.elapsedRealtimeNanos();
      if (remaining <= 0) throw new SocketTimeoutException("Scheduled frame deadline");
      return (int) Math.max(1, remaining / 1000000L);
    }

    private void awaitSockets() throws InterruptedException, IOException {
      if (!socketsReady.await(5, TimeUnit.SECONDS)) throw new IOException("Socket startup deadline");
      synchronized (this) {
        if (started == 0) started = SystemClock.elapsedRealtimeNanos();
      }
    }

    private void identity(JSONObject value, int hash, InetAddress address, int port, int remotePort) {
      synchronized (this) {
        put(value, "object_id", hash); put(value, "local_address", address.getHostAddress());
        put(value, "local_port", port); put(value, "remote_address", destination.getHostAddress());
        put(value, "remote_port", remotePort);
      }
    }

    void pump(boolean stream) {
      String transport = stream ? "tcp" : "udp";
      try {
        if (stream) {
          ScheduledFuture<?> guard = watchdog.schedule(() -> fail("tcp-connect-watchdog"), 5, TimeUnit.SECONDS);
          try { tcp.connect(new InetSocketAddress(destination, 18080), 5000); }
          finally { guard.cancel(false); }
          identity(tcpIdentity, System.identityHashCode(tcp), tcp.getLocalAddress(), tcp.getLocalPort(), 18080);
        } else {
          synchronized (this) {
            if (stopping) return;
            udp = new DatagramSocket();
            udp.connect(destination, 18081);
          }
          identity(udpIdentity, System.identityHashCode(udp), udp.getLocalAddress(), udp.getLocalPort(), 18081);
        }
        socketsReady.countDown();
        awaitSockets();
        Thread reader = new Thread(() -> readReplies(stream), "krtek-session-" + transport + "-reader");
        if (stream) tcpReader = reader; else udpReader = reader;
        reader.start();
        long previous = 0;
        for (int index = 0; index < 1920 && !stopping; index++) {
          long scheduled = started + index * 250000000L;
          if (scheduled >= end) break;
          waitUntil(scheduled);
          if (stopping) break;
          JSONObject record = tick(false, transport, index, scheduled);
          if (record == null) break;
          long now = SystemClock.elapsedRealtimeNanos();
          update(record, "start_ns", now);
          update(record, "cadence_gap_ns", previous == 0 ? 0 : now - previous);
          previous = now;
          if (now - scheduled >= 250000000L) {
            update(record, "outcome", "missed-tick"); fail("local-cadence"); break;
          }
          long deadline = scheduled + 5000000000L;
          int frames = stream && burst.getAndSet(false) ? 40 : 1;
          if (stream && tcpFrames + frames > 1920) { fail("frame-capacity"); break; }
          StringBuilder text = new StringBuilder();
          for (int frame = 0; frame < frames; frame++) {
            int sequence = stream ? tcpFrames++ : index;
            text.append(String.format(Locale.ROOT, "krtek-m3-%s-%s-%04x", id, stream ? "t" : "u", sequence));
          }
          byte[] payload = text.toString().getBytes(StandardCharsets.US_ASCII);
          update(record, "nonce_frames", text.toString()); update(record, "frame_count", frames);
          ScheduledFuture<?> guard = watchdog.schedule(
              stream ? () -> fail("tcp-frame-watchdog") : () -> expireUdp(text.toString()),
              Math.max(1, deadline - SystemClock.elapsedRealtimeNanos()), TimeUnit.NANOSECONDS);
          try {
            update(record, "send_ns", SystemClock.elapsedRealtimeNanos());
            SessionFrame pending = new SessionFrame(record, payload, deadline, guard);
            if (stream) {
              if (!tcpPending.offer(pending)) throw new IOException("TCP in-flight capacity");
              tcp.getOutputStream().write(payload);
            } else {
              synchronized (this) {
                // Coordinate metadata and pending ownership with closeSockets, but
                // never hold the owner lock across a potentially blocking send.
                if (stopping && udp.isClosed()) { cancelFrame(pending); break; }
                if (udpPending.size() >= 21) throw new IOException("UDP in-flight capacity");
                put(record, "socket_id", System.identityHashCode(udp));
                put(record, "local_port", udp.getLocalPort());
                put(record, "local_address", udp.getLocalAddress().getHostAddress());
                udpPending.put(text.toString(), pending);
              }
              try {
                udp.send(new DatagramPacket(payload, payload.length));
                update(record, "send_return_ns", SystemClock.elapsedRealtimeNanos());
              } catch (IOException error) {
                // Preserve the failed nonce without replay. Acceptance is decided from
                // actual Android interface/route logs, never from this catch alone.
                synchronized (this) {
                  if (stopping && udp.isClosed()) cancelFrame(pending);
                  else {
                    put(record, "return_ns", SystemClock.elapsedRealtimeNanos());
                    put(record, "outcome", "udp-send-error");
                    put(record, "error_class", error.getClass().getName());
                    put(record, "send_ioexception", error.toString());
                    put(record, "cause", String.valueOf(error.getCause()));
                  }
                  udpPending.remove(text.toString(), pending);
                  guard.cancel(false);
                }
              }
            }
          } catch (Exception error) {
            update(record, "return_ns", SystemClock.elapsedRealtimeNanos());
            update(record, "outcome", "error"); update(record, "error_class", error.getClass().getName());
            fail(transport + "-exchange");
            guard.cancel(false);
          }
        }
      } catch (Exception error) {
        if (!stopping) fail(transport + "-pump-" + error.getClass().getName());
      }
    }

    void readReplies(boolean stream) {
      SessionFrame pending = null;
      try {
        if (!stream) udp.setSoTimeout(100);
        while (!stopping || (stream ? tcpPump.isAlive() || !tcpPending.isEmpty()
            : udpPump.isAlive() || !udpPending.isEmpty())) {
          if (stream) {
            pending = tcpPending.poll(100, TimeUnit.MILLISECONDS);
            if (pending == null) continue;
            byte[] bytes = new byte[pending.payload.length];
            int offset = 0;
            while (offset < bytes.length) {
              tcp.setSoTimeout(remaining(pending.deadline));
              int count = tcp.getInputStream().read(bytes, offset, bytes.length - offset);
              if (count < 0) throw new EOFException("Session closed before exact echo");
              offset += count;
            }
            if (!Arrays.equals(bytes, pending.payload)) throw new IOException("Session TCP nonce mismatch");
          } else {
            DatagramPacket packet = new DatagramPacket(new byte[46], 46);
            try { udp.receive(packet); } catch (SocketTimeoutException timeout) { continue; }
            String nonce = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.US_ASCII);
            pending = udpPending.remove(nonce);
            if (pending == null || packet.getLength() != 45) throw new IOException("Unknown/duplicate UDP nonce");
          }
          long replied = SystemClock.elapsedRealtimeNanos();
          update(pending.record, "reply_ns", replied); update(pending.record, "bytes", pending.payload.length);
          update(pending.record, "outcome", replied <= pending.deadline ? "reply" : "late-reply");
          if (!stream) {
            update(pending.record, "reply_socket_id", System.identityHashCode(udp));
            update(pending.record, "reply_local_port", udp.getLocalPort());
          }
          pending.guard.cancel(false);
          if (replied > pending.deadline) fail("local-deadline");
          pending = null;
        }
      } catch (Exception error) {
        if (pending != null) {
          update(pending.record, "return_ns", SystemClock.elapsedRealtimeNanos());
          update(pending.record, "outcome", "error");
          update(pending.record, "error_class", error.getClass().getName());
          pending.guard.cancel(false);
        }
        if (!stopping) fail((stream ? "tcp" : "udp") + "-exchange");
      }
    }

    void publicPump() {
      try {
        awaitSockets();
        for (int index = 0; index < 960 && !stopping; index++) {
          long scheduled = started + index * 500000000L;
          if (scheduled >= end) break;
          waitUntil(scheduled);
          if (stopping) break;
          JSONObject record = tick(true, "public-tcp", index, scheduled);
          if (record == null) break;
          try { publicWorkers.execute(() -> publicProbe(record, scheduled)); }
          catch (RejectedExecutionException error) {
            update(record, "outcome", "capacity"); fail("public-capacity"); break;
          }
        }
      } catch (Exception error) { if (!stopping) fail("public-scheduler"); }
    }

    void publicProbe(JSONObject record, long scheduled) {
      Socket socket = new Socket();
      long deadline = scheduled + 1000000000L;
      synchronized (this) {
        publicSockets.add(socket);
        put(record, "socket_id", System.identityHashCode(socket));
      }
      ScheduledFuture<?> guard = null;
      try {
        if (stopping && failure != null) throw new IOException("Session failed");
        guard = watchdog.schedule(() -> {
          update(record, "outcome", "watchdog"); fail("public-watchdog");
        }, Math.max(1, deadline + 100000000L - SystemClock.elapsedRealtimeNanos()), TimeUnit.NANOSECONDS);
        // Leave room for Android's socket-timeout return and owned close. The
        // immutable end-to-end deadline remains the scheduled tick + 1000 ms.
        int timeout = Math.max(1, remaining(deadline) - 25);
        update(record, "start_ns", SystemClock.elapsedRealtimeNanos());
        try {
          socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[] {1, 1, 1, 1}), 443), timeout);
          update(record, "outcome", "connected");
        } catch (IOException error) {
          update(record, "outcome", stopping && failure != null ? "cancelled" : "network-error");
          update(record, "error_class", error.getClass().getName());
        }
        long returned = SystemClock.elapsedRealtimeNanos();
        update(record, "return_ns", returned);
        if (returned > deadline) { update(record, "outcome", "late-return"); fail("public-deadline"); }
      } catch (Exception error) {
        update(record, "outcome", stopping && failure != null ? "cancelled" : "harness-error");
        update(record, "return_ns", SystemClock.elapsedRealtimeNanos());
        update(record, "error_class", error.getClass().getName());
        if (!stopping) fail("public-worker");
      } finally {
        if (guard != null) guard.cancel(false);
        try { socket.close(); } catch (IOException error) { fail("public-close"); }
        long closed = SystemClock.elapsedRealtimeNanos();
        update(record, "close_ns", closed);
        if (closed > deadline) { update(record, "outcome", "late-close"); fail("public-deadline"); }
        synchronized (this) { publicSockets.remove(socket); }
      }
    }

    synchronized Bundle snapshot(int localCursor, int publicCursor) {
      if (localCursor < 0 || localCursor > local.size() || publicCursor < 0 || publicCursor > publicLedger.size())
        return outcome("invalid");
      JSONObject root = new JSONObject();
      put(root, "session_id", id); put(root, "clock", "CLOCK_BOOTTIME");
      put(root, "pid", Process.myPid()); put(root, "uid", Process.myUid());
      put(root, "created_ns", created); put(root, "started_ns", started); put(root, "deadline_ns", end);
      put(root, "stopped_ns", stopped); put(root, "stopping", stopping);
      put(root, "stop_requested_ns", stopRequested);
      put(root, "failure", failure == null ? "" : failure);
      put(root, "stop_reason", stopReason == null ? "" : stopReason);
      put(root, "tcp_socket", tcpIdentity); put(root, "udp_socket", udpIdentity);
      put(root, "local_count", local.size()); put(root, "public_count", publicLedger.size());
      int localEnd = Math.min(local.size(), localCursor + 32);
      int publicEnd = Math.min(publicLedger.size(), publicCursor + 32);
      JSONArray localPage = new JSONArray(), publicPage = new JSONArray();
      for (int i = localCursor; i < localEnd; i++) localPage.put(local.get(i));
      for (int i = publicCursor; i < publicEnd; i++) publicPage.put(publicLedger.get(i));
      put(root, "local", localPage); put(root, "public", publicPage);
      put(root, "local_cursor", localCursor); put(root, "public_cursor", publicCursor);
      put(root, "next_local_cursor", localEnd); put(root, "next_public_cursor", publicEnd);
      Bundle result = outcome("session");
      result.putString("session_id", id); result.putString("session_report", root.toString());
      return result;
    }
  }

  private static final class SessionFrame {
    final JSONObject record;
    final byte[] payload;
    final long deadline;
    final ScheduledFuture<?> guard;
    SessionFrame(JSONObject record, byte[] payload, long deadline, ScheduledFuture<?> guard) {
      this.record = record; this.payload = payload; this.deadline = deadline; this.guard = guard;
    }
  }

  private Bundle lookup(Bundle command) {
    if (!"example.com".equals(command.getString("hostname"))
        || command.containsKey("destination")
        || command.containsKey("port")
        || command.containsKey("nonce")) {
      return outcome("invalid");
    }
    long start = SystemClock.elapsedRealtime();
    Bundle result = outcome("lookup");
    try {
      // One ordinary platform call; no binding, follow-up connect or retry.
      InetAddress[] addresses = InetAddress.getAllByName("example.com");
      if (addresses.length == 0) throw new IllegalStateException("Empty platform lookup");
      result.putString("lookup_outcome", "resolved");
      result.putInt("address_count", addresses.length);
    } catch (Exception error) {
      result.putString("lookup_outcome", "failed");
      result.putString("error_class", error.getClass().getName());
      result.putInt("address_count", 0);
    }
    result.putLong("elapsed_ms", SystemClock.elapsedRealtime() - start);
    return result;
  }

  private static Bundle probeFailure(String kind, Exception error, long start) {
    Bundle result = outcome("harness-failure");
    result.putString("error_kind", kind);
    result.putString("error_class", error.getClass().getName());
    result.putLong("elapsed_ms", SystemClock.elapsedRealtime() - start);
    return result;
  }

  private static byte[] readLimited(InputStream input, int limit) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int count;
    while ((count = input.read(buffer, 0, Math.min(buffer.length, limit + 1 - output.size()))) != -1) {
      if (output.size() + count > limit) throw new IOException("Probe output limit");
      output.write(buffer, 0, count);
    }
    return output.toByteArray();
  }

  private static Bundle exitCheck(ProbeResources resources) {
    long start = SystemClock.elapsedRealtime();
    HttpsURLConnection connection = null;
    try {
      // Platform DNS, proxy selection and TLS trust, exactly as for another app.
      connection = (HttpsURLConnection) new URL("https://am.i.mullvad.net/json").openConnection();
      resources.connection(connection);
      connection.setConnectTimeout(5000);
      connection.setReadTimeout(5000);
      connection.setUseCaches(false);
      connection.setInstanceFollowRedirects(false);
      connection.setRequestProperty("Cache-Control", "no-cache, no-store");
      connection.setRequestProperty("Connection", "close");
      int code = connection.getResponseCode();
      if (code != HttpsURLConnection.HTTP_OK) {
        Bundle result = probeFailure("http-status", new IOException(), start);
        result.putInt("http_status", code);
        return result;
      }
      byte[] bytes;
      try (InputStream input = connection.getInputStream()) {
        bytes = readLimited(input, 16 * 1024);
      }
      JSONTokener tokens = new JSONTokener(new String(bytes, StandardCharsets.UTF_8));
      Object value = tokens.nextValue();
      if (!(value instanceof JSONObject) || tokens.nextClean() != 0) {
        throw new JSONException("Expected one JSON object");
      }
      JSONObject body = (JSONObject) value;
      Object exit = body.get("mullvad_exit_ip");
      Object ip = body.get("ip");
      if (!(exit instanceof Boolean) || !(ip instanceof String)
          || !InetAddresses.isNumericAddress((String) ip)) {
        throw new JSONException("Expected boolean exit and numeric IP");
      }
      InetAddress address = InetAddresses.parseNumericAddress((String) ip);
      Bundle result = outcome("exit-check");
      result.putBoolean("mullvad_exit_ip", (Boolean) exit);
      result.putString("ip", address.getHostAddress());
      result.putInt("family", address.getAddress().length == 4 ? 4 : 6);
      result.putInt("http_status", code);
      result.putLong("elapsed_ms", SystemClock.elapsedRealtime() - start);
      return result;
    } catch (Exception error) {
      return probeFailure("exit-request", error, start);
    }
  }

  private static Bundle icmpCheck(ProbeResources resources) {
    long start = SystemClock.elapsedRealtime();
    Bundle result = outcome("icmp-check");
    try {
      // An ordinary unprivileged ping socket in this consumer's own UID.
      FileDescriptor socket = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMP);
      resources.icmpSocket(socket);
      result.putString("socket_kind", "icmp-dgram");
      byte[] nonce = new byte[32];
      new SecureRandom().nextBytes(nonce);
      result.putByteArray("request_payload", nonce);
      InetAddress destination = InetAddress.getByAddress(new byte[] {1, 1, 1, 1});
      int sent = 0;
      int received = 0;
      for (int sequence = 1; sequence <= 2; sequence++) {
        if (Thread.currentThread().isInterrupted()) throw new IOException("ICMP cancelled");
        long deadline = SystemClock.elapsedRealtime() + 5000;
        Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO, StructTimeval.fromMillis(5000));
        byte[] request = IcmpEcho.request(sequence, nonce);
        result.putInt("attempted", sequence);
        boolean networkOperation = true;
        try {
          if (Os.sendto(socket, request, 0, request.length, 0, destination, 0) != request.length) {
            throw new IOException("Short ICMP datagram send");
          }
          sent++;
          networkOperation = false;
          // Linux assigns and rewrites the echo identifier for SOCK_DGRAM.
          int identifier = ((InetSocketAddress) Os.getsockname(socket)).getPort();
          result.putInt("identifier", identifier);
          for (int reads = 0; ; reads++) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) break;
            if (reads == 16) throw new IOException("ICMP receive capacity");
            Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO, StructTimeval.fromMillis(remaining));
            byte[] reply = new byte[8192];
            InetSocketAddress source = new InetSocketAddress(0);
            networkOperation = true;
            int count = Os.recvfrom(socket, reply, 0, reply.length, 0, source);
            networkOperation = false;
            if (!destination.equals(source.getAddress())) throw new IOException("Unexpected ICMP source");
            int replySequence = IcmpEcho.replySequence(reply, count, identifier, nonce);
            if (replySequence < sequence) continue; // Late reply to our previous request.
            if (replySequence != sequence) throw new IOException("Unexpected ICMP sequence");
            result.putByteArray("reply_" + sequence, Arrays.copyOfRange(reply, 8, count));
            result.putByteArray("packet_" + sequence, Arrays.copyOf(reply, count));
            received++;
            break;
          }
        } catch (ErrnoException error) {
          if (!networkOperation || !(error.errno == OsConstants.EAGAIN || error.errno == OsConstants.ETIMEDOUT
              || error.errno == OsConstants.ENETUNREACH || error.errno == OsConstants.EHOSTUNREACH
              || error.errno == OsConstants.EACCES || error.errno == OsConstants.EPERM
              || error.errno == OsConstants.ECONNREFUSED)) throw error;
          result.putInt("network_errno_" + sequence, error.errno);
        }
      }
      result.putInt("transmitted", sent);
      result.putInt("received", received);
      result.putLong("echo_replies", received);
    } catch (Exception error) {
      result.putString("outcome", "harness-failure");
      result.putString("error_kind", "icmp-socket");
      result.putString("error_class", error.getClass().getName());
      String reason = String.valueOf(error.getMessage());
      result.putString("error_reason", reason.substring(0, Math.min(reason.length(), 256)));
    } finally {
      try { resources.close(); }
      catch (IllegalStateException error) {
        result.putString("outcome", "harness-failure");
        result.putString("error_class", error.getClass().getName());
      }
    }
    result.putLong("elapsed_ms", SystemClock.elapsedRealtime() - start);
    return result;
  }

  static final class IcmpEcho {
    static int checksum(byte[] packet, int length) {
      int sum = 0;
      for (int i = 0; i < length; i += 2) {
        sum += (packet[i] & 255) << 8;
        if (i + 1 < length) sum += packet[i + 1] & 255;
      }
      while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
      return (~sum) & 65535;
    }

    static byte[] request(int sequence, byte[] nonce) {
      byte[] packet = new byte[8 + nonce.length];
      packet[0] = 8;
      packet[6] = (byte) (sequence >>> 8);
      packet[7] = (byte) sequence;
      System.arraycopy(nonce, 0, packet, 8, nonce.length);
      int check = checksum(packet, packet.length);
      packet[2] = (byte) (check >>> 8);
      packet[3] = (byte) check;
      return packet;
    }

    static int replySequence(byte[] packet, int length, int identifier, byte[] nonce) throws IOException {
      if (length != 8 + nonce.length || length > packet.length || packet[0] != 0 || packet[1] != 0
          || ((packet[4] & 255) << 8 | (packet[5] & 255)) != identifier
          || checksum(packet, length) != 0
          || !Arrays.equals(nonce, Arrays.copyOfRange(packet, 8, length))) {
        throw new IOException("Malformed or mismatched ICMP echo reply");
      }
      int sequence = (packet[6] & 255) << 8 | (packet[7] & 255);
      if (sequence < 1 || sequence > 2) throw new IOException("Unexpected ICMP sequence");
      return sequence;
    }
  }

  private static final class ProbeResources implements AutoCloseable {
    private boolean closed;
    private HttpsURLConnection connection;
    private FileDescriptor icmpSocket;

    synchronized void connection(HttpsURLConnection value) throws IOException {
      if (closed) { value.disconnect(); throw new IOException("Probe closed"); }
      connection = value;
    }

    synchronized void icmpSocket(FileDescriptor value) throws IOException {
      icmpSocket = value;
      if (closed) { close(); throw new IOException("Probe closed"); }
    }

    @Override public synchronized void close() {
      closed = true;
      if (connection != null) { connection.disconnect(); connection = null; }
      if (icmpSocket != null) {
        FileDescriptor socket = icmpSocket;
        icmpSocket = null;
        try {
          Os.close(socket);
        } catch (ErrnoException error) {
          throw new IllegalStateException("ICMP socket close failed", error);
        }
      }
    }
  }

  private byte[] tcp(InetAddress address, int port, byte[] payload, int timeout, SocketReport report) throws Exception {
    Socket socket = null;
    Exception primary = null;
    try {
      report.begin("create");
      socket = new Socket();
      report.ok(0);
      report.begin("connect");
      socket.connect(new InetSocketAddress(address, port), timeout);
      report.connectedAt = SystemClock.elapsedRealtimeNanos();
      SocketReport.put(report.root, "local_port", socket.getLocalPort());
      SocketReport.put(report.root, "local_address", socket.getLocalAddress().getHostAddress());
      report.ok(0);
      if (payload == null) return new byte[0];
      report.begin("write");
      socket.getOutputStream().write(payload);
      report.ok(payload.length);
      long deadline = SystemClock.elapsedRealtime() + timeout;
      ByteArrayOutputStream result = new ByteArrayOutputStream();
      byte[] buffer = new byte[256];
      // The emulator proxy is not a reliable half-close/EOF fixture. The
      // forwarder's deterministic tests own that contract; here prove the echo.
      while (result.size() < payload.length) {
        long remaining = deadline - SystemClock.elapsedRealtime();
        report.begin("read");
        if (remaining <= 0) throw new SocketTimeoutException();
        socket.setSoTimeout((int) remaining);
        int count = socket.getInputStream().read(buffer, 0, payload.length - result.size());
        if (count > 0) report.received += count;
        report.ok(count);
        if (count < 0) throw new EOFException("Peer closed before the complete echo");
        result.write(buffer, 0, count);
      }
      report.begin("verify");
      if (!Arrays.equals(result.toByteArray(), payload)) throw new IOException("Echo mismatch");
      report.ok(result.size());
      return result.toByteArray();
    } catch (Exception error) {
      primary = error;
      report.failed(error);
      throw error;
    } finally {
      if (socket != null) {
        report.begin("close");
        try {
          socket.close();
          report.ok(0);
        } catch (Exception error) {
          report.failed(error);
          if (primary != null) primary.addSuppressed(error);
          else throw error;
        } finally {
          report.closedAt = SystemClock.elapsedRealtimeNanos();
        }
      }
    }
  }

  private byte[] udp(InetAddress address, int port, byte[] payload, int timeout, SocketReport report) throws Exception {
    DatagramSocket socket = null;
    try {
      report.begin("create");
      socket = new DatagramSocket();
      socket.setSoTimeout(timeout);
      report.ok(0);
      report.begin("connect");
      socket.connect(address, port);
      report.connectedAt = SystemClock.elapsedRealtimeNanos();
      report.ok(0);
      report.begin("write");
      socket.send(new DatagramPacket(payload, payload.length));
      report.ok(payload.length);
      DatagramPacket packet = new DatagramPacket(new byte[256], 256);
      report.begin("read");
      socket.receive(packet);
      report.received = packet.getLength();
      report.ok(packet.getLength());
      return Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
    } catch (Exception error) {
      report.failed(error);
      throw error;
    } finally {
      if (socket != null) {
        report.begin("close");
        socket.close();
        report.ok(0);
        report.closedAt = SystemClock.elapsedRealtimeNanos();
      }
    }
  }

  /** Bounded metadata only: no reply bytes, credentials or arbitrary payloads. */
  private static final class SocketReport {
    final JSONObject root = new JSONObject();
    final JSONArray events = new JSONArray();
    final long startedAt = SystemClock.elapsedRealtimeNanos();
    long stepAt;
    long connectedAt;
    long closedAt;
    int received;
    String operation = "not-started";

    static void put(JSONObject object, String key, Object value) {
      try {
        object.put(key, value);
      } catch (JSONException error) {
        throw new IllegalStateException(error);
      }
    }

    void begin(String value) {
      operation = value;
      stepAt = SystemClock.elapsedRealtimeNanos();
      event("begin", 0, null);
    }

    void ok(int count) { event("ok", count, null); }

    void failed(Throwable error) { event("failed", 0, error); }

    void event(String phase, int count, Throwable error) {
      JSONObject event = new JSONObject();
      long now = SystemClock.elapsedRealtimeNanos();
      put(event, "operation", operation);
      put(event, "phase", phase);
      put(event, "wall_ms", System.currentTimeMillis());
      put(event, "elapsed_ns", now);
      put(event, "step_elapsed_ns", now - stepAt);
      put(event, "count", count);
      put(event, "received_total", received);
      if (error != null) {
        JSONArray chain = new JSONArray();
        Throwable cause = error;
        for (int depth = 0; cause != null && depth < 8; depth++) {
          JSONObject entry = new JSONObject();
          put(entry, "class", cause.getClass().getName());
          String message = String.valueOf(cause.getMessage());
          put(entry, "message", message.substring(0, Math.min(message.length(), 512)));
          if (cause instanceof android.system.ErrnoException)
            put(entry, "errno", ((android.system.ErrnoException) cause).errno);
          chain.put(entry);
          if (cause.getCause() == cause) break;
          cause = cause.getCause();
        }
        put(event, "cause_chain", chain);
      }
      events.put(event);
    }

    String snapshot() {
      put(root, "events", events);
      put(root, "started_elapsed_ns", startedAt);
      put(root, "connected_elapsed_ns", connectedAt);
      put(root, "closed_elapsed_ns", closedAt);
      put(root, "connection_lifetime_ns", connectedAt == 0 ? 0 : closedAt - connectedAt);
      put(root, "received_total", received);
      return root.toString();
    }
  }

  private void send(Messenger reply, Bundle command, Bundle result) {
    result.putString("request_id", command.getString("request_id"));
    result.putInt("uid", Process.myUid());
    result.putInt("pid", Process.myPid());
    result.putString("package", getPackageName());
    for (String permission : requiredPermissions()) {
      result.putBoolean(
          "permission_" + permission,
          checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED);
    }
    try {
      Message message = Message.obtain();
      message.setData(result);
      reply.send(message);
    } catch (RemoteException ignored) {
      // The requester has gone; never emit private exception messages.
    }
  }
}
