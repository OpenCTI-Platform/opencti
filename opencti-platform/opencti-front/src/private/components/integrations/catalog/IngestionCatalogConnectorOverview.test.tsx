import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import AppIntlProvider from '../../../../components/AppIntlProvider';
import { UserContext, type UserContextType } from '../../../../utils/hooks/useAuth';
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
  compatibility: {
    is_compatible: true,
    latest_compatible_version: '7.260700.0',
    minimum_platform_version: null,
    maximum_platform_version: null,
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

describe('IngestionCatalogConnectorOverview', () => {
  it('displays the latest compatible version above last verified', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: true,
        latest_compatible_version: '7.260828.0',
        minimum_platform_version: null,
        maximum_platform_version: null,
      },
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />);

    expect(screen.getByText('Latest Compatible Version')).toBeInTheDocument();
    expect(screen.getByText('7.260828.0')).toBeInTheDocument();

    const latestCompatibleLabel = screen.getByText('Latest Compatible Version');
    const lastVerifiedLabel = screen.getByText('Last verified');

    expect(latestCompatibleLabel.compareDocumentPosition(lastVerifiedLabel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('displays None when no compatible version exists for the current platform', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: '7.260828.0',
        maximum_platform_version: null,
      },
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />);

    expect(screen.getByText('Latest Compatible Version')).toBeInTheDocument();
    expect(screen.getByText('None')).toBeInTheDocument();
    expect(screen.getByText('This connector is not compatible with your current platform version. Please upgrade your platform to 7.260828.0 or above.')).toBeInTheDocument();
  });

  it('tells the platform is too new when every version has a lower maximum platform version', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: null,
        maximum_platform_version: '7.260700.0',
      },
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />);

    expect(screen.getByText('This connector is not compatible with your current platform version. It supports platform versions up to 7.260700.0.')).toBeInTheDocument();
  });

  it('displays a generic compatibility alert when no platform version can be suggested', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: null,
        maximum_platform_version: null,
      },
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />);

    expect(screen.getByText('This connector is not compatible with your current platform version.')).toBeInTheDocument();
  });

  it('does not display the compatibility alert for a connector that is not managed', () => {
    const connector = buildConnector({
      manager_supported: false,
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: '7.260828.0',
        maximum_platform_version: null,
      },
    });

    testRender(<IngestionCatalogConnectorOverview connector={connector} />);

    expect(screen.queryByText(/This connector is not compatible/)).not.toBeInTheDocument();
  });

  it('translates the compatibility alert and fills in the minimum platform version', () => {
    const connector = buildConnector({
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: '7.260828.0',
        maximum_platform_version: null,
      },
    });
    // testRender provides the intl context outside of the user context, so the locale is set by a nested provider
    const frenchUserContext = { ...createMockUserContext(), locale: 'fr-fr' } as UserContextType;

    testRender(
      <UserContext.Provider value={frenchUserContext}>
        <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
          <IngestionCatalogConnectorOverview connector={connector} />
        </AppIntlProvider>
      </UserContext.Provider>,
    );

    expect(screen.getByText('Ce connecteur n\'est pas compatible avec la version actuelle de votre plateforme. Veuillez mettre à jour votre plateforme vers la version 7.260828.0 ou supérieure.')).toBeInTheDocument();
  });
});
