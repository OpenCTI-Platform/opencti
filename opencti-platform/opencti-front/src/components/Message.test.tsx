import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import { MESSAGING$ } from '../relay/environment';
import Message from './Message';

describe('Message', () => {
  it('should show a warning sent through the messaging service as a warning', async () => {
    testRender(<Message />);
    act(() => MESSAGING$.notifyWarning('Some variables are missing'));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Some variables are missing');
    expect(alert.className).toMatch(/Warning/);
  });
});
