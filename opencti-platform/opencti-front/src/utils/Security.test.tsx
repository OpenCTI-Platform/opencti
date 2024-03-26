import { describe, it, expect } from 'vitest';
import React from 'react';
import Alert from '@mui/material/Alert';
import { screen } from '@testing-library/react';
import Security from './Security';
import { BYPASS, EXPLORE_EXUPDATE, KNOWLEDGE_KNUPDATE } from './hooks/useGranted';
import testRender, { createMockUserContext } from './tests/test-render';

describe('Component: Security validations', () => {
  it('admin with BYPASS should be allowed whatever the required permission is.', () => {
    testRender(
      <Security
        needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
        placeholder={<span>NOT ALLOWED</span>}
      >
        <Alert severity="info" variant="outlined">
          The security allows to see this data.
        </Alert>
      </Security>,
      {
        userContext: createMockUserContext({
          me: {
            name: 'admin',
            user_email: 'admin@opencti.io',
            capabilities: [{ name: BYPASS }],
          },
        }),
      },
    );

    const child = screen.queryByText('The security allows to see this data.');
    expect(child).toBeInTheDocument();
    const notAllowed = screen.queryByText('NOT ALLOWED');
    expect(notAllowed).not.toBeInTheDocument();
  });

  it('user with zero capability should not be allowed whatever the required permission is.', () => {
    testRender(
      <Security
        needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
        placeholder={<span>NOT ALLOWED</span>}
      >
        <Alert severity="info" variant="outlined">
          The security allows to see this data.
        </Alert>
      </Security>,
      {
        userContext: createMockUserContext({
          me: {
            name: 'no capability',
            user_email: 'nocapa@opencti.io',
            capabilities: [],
          },
        }),
      },
    );

    const child = screen.queryByText('The security allows to see this data.');
    expect(child).not.toBeInTheDocument();
    const notAllowed = screen.queryByText('NOT ALLOWED');
    expect(notAllowed).toBeInTheDocument();
  });

  it('user with one capability should not be allowed when all are required.', () => {
    testRender(
      <Security
        needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
        placeholder={<span>NOT ALLOWED</span>}
        matchAll={true}
      >
        <Alert severity="info" variant="outlined">
          The security allows to see this data.
        </Alert>
      </Security>,
      {
        userContext: createMockUserContext({
          me: {
            name: 'knowledge',
            user_email: 'knowledge@opencti.io',
            capabilities: [{ name: KNOWLEDGE_KNUPDATE }],
          },
        }),
      },
    );

    const child = screen.queryByText('The security allows to see this data.');
    expect(child).not.toBeInTheDocument();
    const notAllowed = screen.queryByText('NOT ALLOWED');
    expect(notAllowed).toBeInTheDocument();
  });

  it('user with one capability should be allowed when only one is required.', () => {
    testRender(
      <Security
        needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
        placeholder={<span>NOT ALLOWED</span>}
        matchAll={false}
      >
        <Alert severity="info" variant="outlined">
          The security allows to see this data.
        </Alert>
      </Security>,
      {
        userContext: createMockUserContext({
          me: {
            name: 'knowledge',
            user_email: 'knowledge@opencti.io',
            capabilities: [{ name: KNOWLEDGE_KNUPDATE }],
          },
        }),
      },
    );

    const child = screen.queryByText('The security allows to see this data.');
    expect(child).toBeInTheDocument();
    const notAllowed = screen.queryByText('NOT ALLOWED');
    expect(notAllowed).not.toBeInTheDocument();
  });

  it('user with 2 capability should be allowed when 2 are required.', () => {
    testRender(
      <Security
        needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
        placeholder={<span>NOT ALLOWED</span>}
        matchAll={true}
      >
        <Alert severity="info" variant="outlined">
          The security allows to see this data.
        </Alert>
      </Security>,
      {
        userContext: createMockUserContext({
          me: {
            name: 'twocapa',
            user_email: 'twocapa@opencti.io',
            capabilities: [{ name: KNOWLEDGE_KNUPDATE }, { name: EXPLORE_EXUPDATE }],
          },
        }),
      },
    );

    const child = screen.queryByText('The security allows to see this data.');
    expect(child).toBeInTheDocument();
    const notAllowed = screen.queryByText('NOT ALLOWED');
    expect(notAllowed).not.toBeInTheDocument();
  });
});
