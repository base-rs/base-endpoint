// Released under the MIT License.
// Copyright, 2026, by Samuel Williams.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn socket_wake_reaches_both_pollers_and_completion_releases_their_wakers() {
    let ready = Arc::new(AtomicBool::new(false));
    let socket_waker = Arc::new(Mutex::new(None));
    let polls = Arc::new(AtomicUsize::new(0));
    let transmitter = {
        let ready = ready.clone();
        let socket_waker = socket_waker.clone();
        let polls = polls.clone();
        IoProgress::new(poll_fn(move |cx| {
            polls.fetch_add(1, Ordering::SeqCst);
            if ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                *lock(&socket_waker) = Some(cx.waker().clone());
                Poll::Pending
            }
        }))
    };
    let foreground = Arc::new(Counter::default());
    let background = Arc::new(Counter::default());
    let foreground_waker = Waker::from(foreground.clone());
    let background_waker = Waker::from(background.clone());
    let mut foreground_cx = Context::from_waker(&foreground_waker);
    let mut background_cx = Context::from_waker(&background_waker);
    assert!(transmitter.poll(&mut foreground_cx, true).is_pending());
    assert!(transmitter.poll(&mut background_cx, false).is_pending());
    lock(&socket_waker).take().unwrap().wake();
    assert_eq!(foreground.0.load(Ordering::SeqCst), 1);
    assert_eq!(background.0.load(Ordering::SeqCst), 1);

    ready.store(true, Ordering::SeqCst);
    assert!(matches!(
        transmitter.poll(&mut foreground_cx, true),
        Poll::Ready(Ok(()))
    ));
    let completed_polls = polls.load(Ordering::SeqCst);
    assert!(matches!(
        transmitter.poll(&mut background_cx, false),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(polls.load(Ordering::SeqCst), completed_polls);
    assert_eq!(Arc::strong_count(&foreground), 2);
    assert_eq!(Arc::strong_count(&background), 2);
}
