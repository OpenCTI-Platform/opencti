import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { BYPASS } from '../../../../utils/hooks/useGranted';
import type { IngestionConnector } from './types';
import IngestionCatalogConnectorHeader from './IngestionCatalogConnectorHeader';

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
  compatibility: {
    is_compatible: true,
    latest_compatible_version: '7.260700.0',
    minimum_platform_version: '7.260700.0',
  },
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

const buildUserContext = () => ({
  ...createMockUserContext({
    me: {
      name: 'admin',
      user_email: 'admin@opencti.io',
      capabilities: [{ name: BYPASS }],
      capabilitiesInDraft: [],
    },
  }),
});

describe('IngestionCatalogConnectorHeader', () => {
  it('disables Deploy when no compatible version exists', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: '7.260828.0',
      },
    });

    testRender(
      <IngestionCatalogConnectorHeader connector={connector} isEnterpriseEdition={true} onClickDeploy={() => {}} />,
      { userContext: buildUserContext() },
    );

    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
  });

  it('keeps Deploy enabled when a compatible version exists', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: true,
        latest_compatible_version: '7.260828.0',
        minimum_platform_version: '7.260828.0',
      },
    });

    testRender(
      <IngestionCatalogConnectorHeader connector={connector} isEnterpriseEdition={true} onClickDeploy={() => {}} />,
      { userContext: buildUserContext() },
    );

    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('does not render Deploy for unmanaged connectors', () => {
    const connector = buildConnector({ manager_supported: false });

    testRender(
      <IngestionCatalogConnectorHeader connector={connector} isEnterpriseEdition={true} onClickDeploy={() => {}} />,
      { userContext: buildUserContext() },
    );

    expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
  });
});