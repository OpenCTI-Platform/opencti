import { describe, it, expect } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { TokenListBase } from './TokenList';
import { TokenList_node$data } from '@components/profile/api_tokens/__generated__/TokenList_node.graphql';

describe('Component: TokenList', () => {
  const mockNode = {
    api_tokens: [
      {
        id: 'token-1',
        name: 'Test Token 1',
        created_at: '2023-01-01T10:00:00.000Z',
        expires_at: null,
        masked_token: '***1234',
      },
      {
        id: 'token-2',
        name: 'Expired Token',
        created_at: '2022-01-01T10:00:00.000Z',
        expires_at: '2022-02-01T10:00:00.000Z', // Past date
        masked_token: '***5678',
      },
    ],
  } as unknown as TokenList_node$data;

  it('should render list of tokens', () => {
    testRender(<TokenListBase node={mockNode} />);

    expect(screen.getByText('Test Token 1')).toBeInTheDocument();
    expect(screen.getByText('Unlimited')).toBeInTheDocument();

    expect(screen.getByText('Expired Token')).toBeInTheDocument();
    expect(screen.getByText('Expired')).toBeInTheDocument();
  });

  it('should render empty state', () => {
    const node = { api_tokens: [] } as unknown as TokenList_node$data;
    testRender(<TokenListBase node={node} />);
    expect(screen.getByText(/No tokens found/)).toBeInTheDocument();
  });
});
