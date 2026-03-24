/**
 * A timer that can be skipped early, resolving the promise immediately.
 * Used in manager loops to allow clean shutdown without waiting for the full delay.
 *
 * Usage:
 *   const timer = new SkippableTimer();
 *   await timer.start(5_000); // waits up to 5 seconds
 *   timer.skip(); // resolves immediately from another context
 */
export class SkippableTimer {
  private timeoutId: ReturnType<typeof setTimeout> | null = null;

  private resolve: (() => void) | null = null;

  skip() {
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
