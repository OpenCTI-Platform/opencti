import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { createTheme, ThemeOptions } from '@mui/material/styles';
import testRender from '../../../../../utils/tests/test-render';
import ThemeDark from '../../../../../components/ThemeDark';
import { AuditLine } from './AuditLine';
import { AuditLine_node$key } from './__generated__/AuditLine_node.graphql';

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  useFragment: (_: unknown, ref: unknown) => ref,
}));

const dataColumns = {
  timestamp: { label: 'Date', width: '15%', isSortable: false },
  user: { label: 'User', width: '15%', isSortable: false },
  event_type: { label: 'Event type', width: '10%', isSortable: false },
  event_scope: { label: 'Event scope', width: '10%', isSortable: false },
  message: { label: 'Message', width: '50%', isSortable: false },
};

// An automatic lock of the local authentication lockout, as the activity listener stores it
const lockEvent = (message: string) => ({
  id: 'log-id',
  entity_type: 'Activity',
  event_type: 'authentication',
  event_scope: 'lock',
  event_status: 'error',
  timestamp: '2026-11-12T10:00:00.000Z',
  context_uri: null,
  user: { id: 'user-id', name: 'victim' },
  context_data: { entity_id: null, entity_type: null, entity_name: null, message, from_id: null, to_id: null },
}) as unknown as AuditLine_node$key;

const renderLine = (message: string) => testRender(
  <AuditLine node={lockEvent(message)} dataColumns={dataColumns} onLabelClick={vi.fn()} />,
);

describe('AuditLine, lock of the local authentication lockout', () => {
  it('shows a temporary lock with a lock icon, in the error color', () => {
    renderLine('detects `account lock` for `victim@opencti.io`: locked for `15 minutes` after `10` failed authentication attempts');
    const errorColor = createTheme(ThemeDark() as ThemeOptions).palette.error.main;
    expect(screen.getByTestId('LockOutlineIcon')).toHaveStyle({ color: errorColor });
    expect(screen.getByText('authentication')).toBeInTheDocument();
    expect(screen.getByText('lock')).toBeInTheDocument();
    expect(screen.getByRole('button')).toHaveTextContent(
      'victim detects account lock for victim@opencti.io: locked for 15 minutes after 10 failed authentication attempts',
    );
  });

  it('shows a permanent lock until an administrator unlocks the account', () => {
    renderLine('detects `account lock` for `victim@opencti.io`: locked until an administrator unlocks it after `10` failed authentication attempts');
    expect(screen.getByTestId('LockOutlineIcon')).toBeInTheDocument();
    expect(screen.getByRole('button')).toHaveTextContent(
      'victim detects account lock for victim@opencti.io: locked until an administrator unlocks it after 10 failed authentication attempts',
    );
  });
});
