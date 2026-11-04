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
import java.security.SecureRandom;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
  private final Handler main = new Handler(Looper.getMainLooper());
  private boolean expired;
  private volatile ProbeResources activeProbe;
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
  public void onDestroy() {
    expired = true;
    main.removeCallbacksAndMessages(null);
    worker.shutdownNow();
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
    FutureTask<Void> task =
        new FutureTask<>(
            () -> {
              Bundle result = execute(command);
              if (completed.compareAndSet(false, true)) send(reply, command, result);
              return null;
            });
    Runnable deadline =
        () -> {
          if (completed.compareAndSet(false, true)) {
            expired = true;
            task.cancel(true);
            worker.shutdownNow();
            ProbeResources active = activeProbe;
            if (active != null) active.close();
            send(reply, command, outcome("deadline"));
          }
        };
    try {
      worker.execute(task);
      String transport = command.getString("transport");
      main.postDelayed(deadline,
          ("lookup".equals(transport) || "exit-check".equals(transport) || "icmp-check".equals(transport))
              ? 30000L : 12000L);
    } catch (RejectedExecutionException ignored) {
      completed.set(true);
      send(reply, command, outcome("capacity"));
    }
  }

  private Bundle execute(Bundle command) {
    String transport = command.getString("transport");
    if ("identity".equals(transport)) {
      Bundle result = outcome("identity");
      result.putString("application_class", getApplication().getClass().getName());
      return result;
    }
    if ("lookup".equals(transport)) return lookup(command);
    if ("exit-check".equals(transport) || "icmp-check".equals(transport)) {
      if (command.size() != 2 || !command.containsKey("request_id")) return outcome("invalid");
      ProbeResources resources = new ProbeResources();
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
