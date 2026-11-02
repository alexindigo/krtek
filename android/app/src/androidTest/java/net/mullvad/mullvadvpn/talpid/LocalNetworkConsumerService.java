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
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
            send(reply, command, outcome("deadline"));
          }
        };
    try {
      worker.execute(task);
      main.postDelayed(deadline, "lookup".equals(command.getString("transport")) ? 30000L : 12000L);
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
