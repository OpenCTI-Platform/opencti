import { describe, expect, it } from 'vitest';
import { getDataID, handleError, handleErrorInForm, MESSAGING$ } from './environment';

describe('getDataID', () => {
  it('does not collide a Connector with a Synchronizer sharing the same id (sync twin connector)', () => {
    const id = '3753c425-0000-4000-8000-000000000000';
    expect(getDataID({ id }, 'Connector')).not.toBe(getDataID({ id }, 'Synchronizer'));
  });

  it('keeps the raw id for other types', () => {
    expect(getDataID({ id: 'abc' }, 'Synchronizer')).toBe('abc');
  });
});

describe('form and mutation errors keep the full error', () => {
  const accessRequired = { message: 'Restricted entity already exists, you can request access', extensions: { code: 'ACCESS_REQUIRED', data: { entityIds: ['e1'] } } };
  const relayError = { res: { errors: [accessRequired] } };

  it.each([
    ['handleErrorInForm', () => handleErrorInForm(relayError as unknown as Error, () => {})],
    ['handleError', () => handleError(relayError)],
  ])('%s forwards the error so the Request Access button can show', async (_name, run) => {
    const received: unknown[] = [];
    const subscription = MESSAGING$.messages.subscribe({ next: (messages) => received.push(...messages) });
    run();
    // the message bus is debounced
    await new Promise((resolve) => setTimeout(resolve, 600));
    subscription.unsubscribe();
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ type: 'error', fullError: accessRequired });
  });
});
