import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import IngestionHealthChip from './IngestionHealthChip';

describe('IngestionHealthChip', () => {
  it('shows the translated status', () => {
    testRender(<IngestionHealthChip status="critical" summary="No ping received since 2026-10-07T10:00:00.000Z" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('falls back to Unknown on a status this front does not know yet', () => {
    testRender(<IngestionHealthChip status="%future added value" summary="Something" />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });

  it('shows the server summary and every detail line in its tooltip', async () => {
    const { user } = testRender(
      <IngestionHealthChip status="unknown" summary="Pinging every 40 seconds, data intake not evaluated yet" details={['⚠ User is not a service account']} />,
    );
    await user.hover(screen.getByText('Unknown'));
    expect((await screen.findAllByText('Pinging every 40 seconds, data intake not evaluated yet')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('⚠ User is not a service account')).length).toBeGreaterThan(0);
  });
});
