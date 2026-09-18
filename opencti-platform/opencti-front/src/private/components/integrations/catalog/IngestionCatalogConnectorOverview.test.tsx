import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import type { IngestionConnector } from './types';
import IngestionCatalogConnectorOverview from './IngestionCatalogConnectorOverview';

const buildConnector = (overrides: Partial<IngestionConnector> = {}): IngestionConnector => ({
  title: 'CrowdStrike Falcon Intel',
  slug: 'crowdstrike-falcon-intel',
  description: 'Connector overview',
  short_description: 'Short description',
  logo: 'https://example.test/logo.png',
  use_cases: ['Enrichment'],
  solution_categories: null,
  license_type: null,
  verified: true,
  last_verified_date: '2026-09-18',
  playbook_supported: false,
  max_confidence_level: 100,
  support_version: '7.260700.0',
  subscription_link: 'https://example.test/vendor',
  source_code: 'https://example.test/source',
  manager_supported: true,
  container_version: '7.260700.0',
  container_image: 'example/test:7.260700.0',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'test-schema',
    type: 'object',
    properties: {},
    required: [],
    additionalProperties: false,
  },
  ...overrides,
});

describe('IngestionCatalogConnectorOverview', () => {
  it('displays the latest compatible version above last verified', () => {
    const connector = buildConnector({
      versions: [
        { version: '7.260950.0', min_platform_version: '7.260950.0' },
        { version: '7.260828.0', min_platform_version: '7.260828.0' },
        { version: '7.260700.0', min_platform_version: '7.260700.0' },
      ],
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />, {
      userContext: {
        ...createMockUserContext({}),
        about: { version: '7.260901.0' },
      },
    });

    expect(screen.getByText('Latest Compatible Version')).toBeInTheDocument();
    expect(screen.getByText('7.260828.0')).toBeInTheDocument();

    const latestCompatibleLabel = screen.getByText('Latest Compatible Version');
    const lastVerifiedLabel = screen.getByText('Last verified');

    expect(latestCompatibleLabel.compareDocumentPosition(lastVerifiedLabel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('displays None when no compatible version exists for the current platform', () => {
    const connector = buildConnector({
      versions: [
        { version: '7.260950.0', min_platform_version: '7.260950.0' },
      ],
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />, {
      userContext: {
        ...createMockUserContext({}),
        about: { version: '7.260901.0' },
      },
    });

    expect(screen.getByText('Latest Compatible Version')).toBeInTheDocument();
    expect(screen.getByText('None')).toBeInTheDocument();
  });
});