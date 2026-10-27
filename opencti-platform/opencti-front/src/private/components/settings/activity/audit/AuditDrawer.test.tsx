import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import useGranted from '../../../../../utils/hooks/useGranted';
import testRender from '../../../../../utils/tests/test-render';
import AuditDrawer from './AuditDrawer';

vi.mock('../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../utils/hooks/useGranted')>()),
  default: vi.fn(),
}));

const renderDrawer = async (fileId: string | null) => {
  const { relayEnv } = testRender(<AuditDrawer open onClose={vi.fn()} logId="log-id" />);
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      Log: () => ({
        id: 'log-id',
        entity_type: 'History',
        event_type: 'command',
        event_scope: 'import',
        event_status: 'success',
        timestamp: '2026-10-27T10:00:00.000Z',
        context_uri: null,
        raw_data: null,
        user: { id: 'user-id', name: 'admin' },
        context_data: { file_id: fileId, entity_id: null, entity_type: null, entity_name: null, message: 'imports a configuration preset', from_id: null, to_id: null, changes: [] },
      }),
    }));
  });
};

describe('AuditDrawer import report', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('links the import report to a BYPASS user', async () => {
    (useGranted as Mock).mockReturnValue(true);
    await renderDrawer('config_preset/history/id/import-report.json');
    expect(await screen.findByRole('link', { name: 'Download report' })).toHaveAttribute('href', expect.stringContaining(encodeURIComponent('config_preset/history/id/import-report.json')));
  });

  it('hides the link from an activity viewer without BYPASS', async () => {
    (useGranted as Mock).mockReturnValue(false);
    await renderDrawer('config_preset/history/id/import-report.json');
    expect(await screen.findByText('imports a configuration preset')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Download report' })).not.toBeInTheDocument();
  });

  it('shows no link when the event has no file', async () => {
    (useGranted as Mock).mockReturnValue(true);
    await renderDrawer(null);
    expect(await screen.findByText('imports a configuration preset')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Download report' })).not.toBeInTheDocument();
  });
});
