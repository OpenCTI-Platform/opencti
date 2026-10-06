import { screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import ConnectorCatalogIdentityDialog from './ConnectorCatalogIdentityDialog';

const CATALOG_OPTIONS = [
  { slug: 'virustotal', title: 'VirusTotal', logo: '/logo/virustotal.png', connector_type: 'INTERNAL_ENRICHMENT', short_description: 'File reputation' },
  { slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', connector_type: 'EXTERNAL_IMPORT', short_description: 'Malicious URLs' },
];

const renderDialog = (catalogIdentity: Record<string, unknown> | null, onClose = vi.fn(), catalogSlugManual: string | null = null) => {
  const rendered = testRender(
    <ConnectorCatalogIdentityDialog
      open
      onClose={onClose}
      connector={{ id: 'connector-id', connector_type: 'EXTERNAL_IMPORT', catalog_identity: catalogIdentity as never, catalog_slug_manual: catalogSlugManual }}
    />,
  );
  rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
    Query: () => ({ connectorCatalogIdentityOptions: CATALOG_OPTIONS }),
  }));
  return rendered;
};

describe('ConnectorCatalogIdentityDialog', () => {
  it('should preview the current catalog entry and wait for another choice', async () => {
    renderDialog({ slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', source: 'manual' });

    await waitFor(() => {
      expect(screen.getByTestId('catalog-identity-preview')).toBeTruthy();
    });
    expect(screen.getByText('Malicious URLs')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Save' }).hasAttribute('disabled')).toBe(true);
  });

  it('should not save before a catalog entry is chosen', async () => {
    renderDialog(null);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save' })).toBeTruthy();
    });
    expect(screen.getByRole('button', { name: 'Save' }).hasAttribute('disabled')).toBe(true);
    expect(screen.queryByTestId('catalog-identity-preview')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Use automatic identification' })).toBeNull();
  });

  it('should return a connector chosen by hand to automatic identification', async () => {
    const onClose = vi.fn();
    const { relayEnv, user } = renderDialog({ slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', source: 'manual' }, onClose);

    await user.click(await screen.findByRole('button', { name: 'Use automatic identification' }));

    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.operation.name).toBe('ConnectorCatalogIdentityDialogMutation');
    expect(operation.request.variables).toEqual({ id: 'connector-id', slug: null });
    relayEnv.mock.resolve(operation, MockPayloadGenerator.generate(operation, {
      Connector: () => ({ id: 'connector-id', catalog_identity: null }),
    }));
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('should let a choice made by hand be removed after its entry left the catalog', async () => {
    // The stored choice no longer resolves, so the identity comes from the name: the choice is still there.
    const { relayEnv, user } = renderDialog({ slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', source: 'name' }, vi.fn(), 'removed-entry');

    await user.click(await screen.findByRole('button', { name: 'Use automatic identification' }));

    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables).toEqual({ id: 'connector-id', slug: null });
  });

  it('should refresh the catalog entries every time the dialog opens', async () => {
    const { relayEnv, rerender } = renderDialog(null);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save' })).toBeTruthy();
    });
    const connector = { id: 'connector-id', connector_type: 'EXTERNAL_IMPORT', catalog_identity: null, catalog_slug_manual: null };
    rerender(<ConnectorCatalogIdentityDialog open={false} onClose={vi.fn()} connector={connector} />);
    rerender(<ConnectorCatalogIdentityDialog open onClose={vi.fn()} connector={connector} />);
    await waitFor(() => {
      const operation = relayEnv.mock.getMostRecentOperation();
      expect(operation.request.node.operation.name).toBe('ConnectorCatalogIdentityDialogOptionsQuery');
    });
  });

  it('should not offer automatic identification for an entry found automatically', async () => {
    renderDialog({ slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', source: 'name' });

    await waitFor(() => {
      expect(screen.getByTestId('catalog-identity-preview')).toBeTruthy();
    });
    expect(screen.queryByRole('button', { name: 'Use automatic identification' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Save' }).hasAttribute('disabled')).toBe(false);
  });
});
