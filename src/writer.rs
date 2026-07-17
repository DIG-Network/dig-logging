//! A non-blocking, LOSSY line writer (SPEC §4.4).
//!
//! A saturated logging pipeline must NEVER stall a service's serve path, so the file sink hands each
//! rendered line to a bounded channel drained by a dedicated writer thread. When the channel is full
//! the line is DROPPED and a counter is bumped rather than blocking the caller — loss is visible via
//! [`LossyWriter::dropped`], which [`init`](crate::init) surfaces as a `WARN` event.
//!
//! Each `write_all` from the JSON layer carries exactly one complete line, so one buffer = one
//! channel message. The writer thread owns the rotating file appender (daily rotation + retention).

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// The bounded queue depth. Generous enough to absorb bursts; past it, lines drop (SPEC §4.4).
const QUEUE_CAPACITY: usize = 8192;

/// How long the guard waits for the writer thread to flush on shutdown before giving up.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// A message on the writer channel: a rendered line, or a flush barrier that acks when drained.
enum Message {
    Line(Vec<u8>),
    Flush(SyncSender<()>),
}

/// The `Write`/`MakeWriter` handle installed into the JSON layer. Cheap to clone (it is just a
/// channel sender plus a shared drop counter).
#[derive(Clone)]
pub struct LossyWriter {
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}

impl LossyWriter {
    /// The total number of lines dropped under backpressure since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Write for LossyWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Never block the caller: a full queue drops the line and records the loss.
        if self.tx.try_send(Message::Line(buf.to_vec())).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// `tracing_subscriber` needs a `MakeWriter`; each event gets a fresh clone of the sender handle.
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LossyWriter {
    type Writer = LossyWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Holds the writer thread alive and flushes it on drop (SPEC §4.4). Dropping it asks the thread to
/// drain + flush, waits briefly for the ack, then lets the process continue shutting down.
pub struct WriterGuard {
    tx: SyncSender<Message>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        // Non-blocking send: if the queue is saturated (a wedged sink) we skip the flush wait rather
        // than block shutdown forever — the lines already handed to the OS are the durable record.
        let (ack_tx, ack_rx) = sync_channel(1);
        if self.tx.try_send(Message::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(FLUSH_TIMEOUT);
        }
        if let Some(handle) = self.handle.take() {
            // The global subscriber keeps a sender clone, so the thread will not exit on its own;
            // we do not join (that would hang). The flush above is the durability guarantee.
            drop(handle);
        }
    }
}

/// Spawn the writer thread draining into `sink`, returning the clonable [`LossyWriter`] handle and a
/// [`WriterGuard`] that flushes on drop. `sink` is any blocking writer (the rolling file appender).
pub fn spawn<W: Write + Send + 'static>(mut sink: W) -> (LossyWriter, WriterGuard) {
    let (tx, rx): (SyncSender<Message>, Receiver<Message>) = sync_channel(QUEUE_CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));

    let handle = std::thread::Builder::new()
        .name("dig-logging-writer".into())
        .spawn(move || {
            while let Ok(message) = rx.recv() {
                match message {
                    Message::Line(bytes) => {
                        let _ = sink.write_all(&bytes);
                    }
                    Message::Flush(ack) => {
                        let _ = sink.flush();
                        let _ = ack.send(());
                    }
                }
            }
        })
        .expect("spawn dig-logging writer thread");

    let writer = LossyWriter {
        tx: tx.clone(),
        dropped,
    };
    let guard = WriterGuard {
        tx,
        handle: Some(handle),
    };
    (writer, guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A sink that records everything written, for asserting the thread drains lines.
    #[derive(Clone, Default)]
    struct VecSink(Arc<Mutex<Vec<u8>>>);
    impl Write for VecSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lines_reach_the_sink() {
        let sink = VecSink::default();
        let (mut writer, guard) = spawn(sink.clone());
        writer.write_all(b"hello\n").unwrap();
        writer.write_all(b"world\n").unwrap();
        drop(guard); // flushes
        assert_eq!(&*sink.0.lock().unwrap(), b"hello\nworld\n");
    }

    #[test]
    fn full_queue_drops_and_counts() {
        // A sink that blocks forever wedges the writer thread, so the bounded queue fills and
        // subsequent writes are dropped + counted rather than blocking the caller.
        struct BlockingSink;
        impl Write for BlockingSink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_secs(3600));
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (mut writer, _guard) = spawn(BlockingSink);
        for _ in 0..(QUEUE_CAPACITY + 200) {
            writer.write_all(b"x\n").unwrap();
        }
        assert!(
            writer.dropped() > 0,
            "a wedged sink must drop lines, not block"
        );
    }
}
