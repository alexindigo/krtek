package net.mullvad.mullvadvpn.talpid;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/** Exercises the real stop owner with a producer held at its submission boundary, without traffic. */
public class LocalNetworkConsumerSessionTest {
  private final Class<?> type;

  public LocalNetworkConsumerSessionTest() throws Exception {
    type = Class.forName(LocalNetworkConsumerService.class.getName() + "$Session");
  }

  private Object session() throws Exception {
    Constructor<?> constructor = type.getDeclaredConstructor(InetAddress.class, int.class);
    constructor.setAccessible(true);
    return constructor.newInstance(InetAddress.getLoopbackAddress(), 30000);
  }

  private Object field(Object session, String name) throws Exception {
    Field field = type.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(session);
  }

  private void producer(Object session, Thread producer) throws Exception {
    set(session, "publicPump", producer);
  }

  private void set(Object session, String name, Object value) throws Exception {
    Field field = type.getDeclaredField(name);
    field.setAccessible(true);
    field.set(session, value);
  }

  private void stop(Object session) throws Exception {
    Method stop = type.getDeclaredMethod("stop", String.class);
    stop.setAccessible(true);
    stop.invoke(session, "requested");
  }

  @Test
  public void joinsAdmittedProducerBeforeClosingWorkerAdmission() throws Exception {
    Object session = session();
    ThreadPoolExecutor workers = (ThreadPoolExecutor) field(session, "publicWorkers");
    CountDownLatch admitted = new CountDownLatch(1), release = new CountDownLatch(1);
    AtomicReference<Throwable> error = new AtomicReference<>();
    JSONObject record = new JSONObject();
    Socket owned = new Socket();
    @SuppressWarnings("unchecked")
    java.util.Set<Socket> sockets = (java.util.Set<Socket>) field(session, "publicSockets");
    sockets.add(owned);
    Thread pump = new Thread(() -> {
      admitted.countDown();
      try {
        assertTrue(release.await(2, TimeUnit.SECONDS));
        workers.execute(() -> {
          try {
            owned.close();
            record.put("outcome", "closed");
          } catch (Exception failure) { error.set(failure); }
        });
      } catch (Throwable failure) { error.set(failure); }
    });
    producer(session, pump);
    pump.start();
    assertTrue(admitted.await(1, TimeUnit.SECONDS));
    Thread stopper = new Thread(() -> {
      try { stop(session); } catch (Throwable failure) { error.set(failure); }
    });
    try {
      stopper.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
      while (!(boolean) field(session, "stopping") && System.nanoTime() < deadline) Thread.yield();
      assertTrue((boolean) field(session, "stopping"));
      assertTrue(stopper.isAlive());
      assertFalse(workers.isShutdown(), "worker admission closed before producer join");
    } finally {
      release.countDown();
      pump.join(2000);
      stopper.join(7000);
    }
    assertNull(error.get());
    assertFalse(pump.isAlive());
    assertFalse(stopper.isAlive());
    assertTrue(workers.isTerminated());
    assertTrue(owned.isClosed());
    assertTrue(((Socket) field(session, "tcp")).isClosed());
    assertEquals("closed", record.getString("outcome"));
    assertNull(field(session, "failure"));
    assertTrue((long) field(session, "stopped") > 0);
  }

  @Test
  public void genuineWorkerSaturationRemainsAFailure() throws Exception {
    Object session = session();
    ThreadPoolExecutor workers = (ThreadPoolExecutor) field(session, "publicWorkers");
    CountDownLatch running = new CountDownLatch(3), release = new CountDownLatch(1);
    try {
      for (int i = 0; i < 3; i++) workers.execute(() -> {
        running.countDown();
        try { release.await(); } catch (InterruptedException failure) { Thread.currentThread().interrupt(); }
      });
      assertTrue(running.await(1, TimeUnit.SECONDS));
      assertThrows(RejectedExecutionException.class, () -> workers.execute(() -> {}));
      Method fail = type.getDeclaredMethod("fail", String.class);
      fail.setAccessible(true);
      fail.invoke(session, "public-capacity");
    } finally {
      release.countDown();
      stop(session);
    }
    assertEquals("public-capacity", field(session, "failure"));
    assertTrue(workers.isTerminated());
  }

  @Test
  public void joinsReadersInstalledWhileTheirProducerIsStopping() throws Exception {
    Object session = session();
    CountDownLatch admitted = new CountDownLatch(1), release = new CountDownLatch(1);
    CountDownLatch readerFinished = new CountDownLatch(1);
    CountDownLatch releaseReader = new CountDownLatch(1), readerJoined = new CountDownLatch(1);
    AtomicReference<Throwable> error = new AtomicReference<>();
    Thread reader = new Thread(() -> {
      try { releaseReader.await(); } catch (InterruptedException failure) { error.set(failure); }
      readerFinished.countDown();
    });
    Thread pump = new Thread(() -> {
      admitted.countDown();
      try {
        assertTrue(release.await(2, TimeUnit.SECONDS));
        set(session, "tcpReader", reader);
        reader.start();
      } catch (Throwable failure) { error.set(failure); }
    });
    // Only the actual producer join releases the reader; only the actual reader
    // join signals completion. Skipping reader joins cannot pass after a delay.
    set(session, "joined", (java.util.function.Consumer<Thread>) thread -> {
      if (thread == pump) releaseReader.countDown();
      if (thread == reader) readerJoined.countDown();
    });
    set(session, "tcpPump", pump);
    pump.start();
    assertTrue(admitted.await(1, TimeUnit.SECONDS));
    Thread stopper = new Thread(() -> {
      try { stop(session); } catch (Throwable failure) { error.set(failure); }
    });
    try {
      stopper.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
      while (!(boolean) field(session, "stopping") && System.nanoTime() < deadline) Thread.yield();
      assertTrue((boolean) field(session, "stopping"));
      release.countDown();
      assertTrue(readerJoined.await(2, TimeUnit.SECONDS), "late-installed reader join was skipped");
      stopper.join(7000);
      assertFalse(stopper.isAlive());
      assertEquals(0, readerFinished.getCount(), "stop returned before the late-installed reader joined");
      assertFalse(reader.isAlive());
      assertNull(field(session, "failure"));
      assertNull(error.get());
    } finally {
      release.countDown();
      releaseReader.countDown();
      pump.join(2000);
      reader.join(2000);
      stopper.join(7000);
    }
  }
}
