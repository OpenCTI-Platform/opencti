/**
 * A timer that can be interrupted, resolving the promise immediately.
 * Used in manager loops to allow clean shutdown without waiting for the full delay.
 *
 * Usage:
 *   const timer = new InterruptibleTimer();
 *   await timer.start(5_000); // waits up to 5 seconds
 *   timer.interrupt(); // resolves immediately from another context
 */
export class InterruptibleTimer {
  private timeoutId: ReturnType<typeof setTimeout> | null = null;

  private resolve: (() => void) | null = null;

  interrupt() {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
    this.resolve?.();
    this.resolve = null;
  }

  async start(timeMs: number): Promise<void> {
    // Clean up any previous timer before starting a new one
    if (this.timeoutId !== null) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
    return new Promise<void>((resolve) => {
      this.resolve = resolve;
      this.timeoutId = setTimeout(() => {
        this.resolve?.();
        this.resolve = null;
        this.timeoutId = null;
      }, timeMs);
    });
  }
}
