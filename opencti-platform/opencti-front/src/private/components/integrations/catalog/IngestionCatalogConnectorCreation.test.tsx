import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import IngestionCatalogConnectorCreation from './IngestionCatalogConnectorCreation';
import type { IngestionConnector } from './types';

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    graphql: (strings: TemplateStringsArray) => strings[0],
    useMutation: () => [vi.fn()],
  };
});

vi.mock('@cfworker/json-schema', () => ({
  Validator: class {
    schema: Record<string, unknown>;

    constructor(schema: Record<string, unknown>) {
      this.schema = schema;
    }

    validate() {
      return { errors: [] };
    }
  },
}));

vi.mock('../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('@components/common/drawer/Drawer', () => ({
  __esModule: true,
  default: ({ open, children, header, title }: {
    open: boolean;
    children: React.ReactNode;
    header?: React.ReactNode;
    title: string;
  }) => (open ? <div><div>{title}</div>{header}{children}</div> : null),
}));

vi.mock('@components/data/IngestionCreationUserHandling', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('@components/data/connectors/ConnectorDeploymentBanner', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('@jsonforms/react', () => ({
  JsonForms: () => null,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormArrayRenderer', () => ({
  __esModule: true,
  default: () => null,
  jsonFormArrayTester: () => -1,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormInputRenderer', () => ({
  __esModule: true,
  default: () => null,
  jsonFormInputTester: () => -1,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormEnumRenderer', () => ({
  __esModule: true,
  default: () => null,
  jsonFormEnumTester: () => -1,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormBooleanRenderer', () => ({
  __esModule: true,
  default: () => null,
  jsonFormBooleanTester: () => -1,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormUnsupportedType', () => ({
  __esModule: true,
  default: () => null,
  jsonFormUnsupportedTypeTester: () => -1,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormPasswordRenderer', () => ({
  __esModule: true,
  JsonFormPasswordRenderer: () => null,
  jsonFormPasswordTester: () => -1,
}));

vi.mock('@components/integrations/catalog/utils/JsonFormDeprecatedRenderer', () => ({
  __esModule: true,
  default: () => null,
  jsonFormDeprecatedTester: () => -1,
}));

vi.mock('./utils/JsonFormVerticalLayout', () => ({
  __esModule: true,
  JsonFormVerticalLayout: () => null,
  jsonFormVerticalLayoutTester: () => -1,
}));

vi.mock('@components/integrations/catalog/IngestionCatalogUnverifiedDeploymentPopover', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../../../../components/TextField', () => ({
  __esModule: true,
  default: ({ field, form, label, name, onChange, disabled }: {
    field: { name: string };
    form: { values: Record<string, string>; setFieldValue: (fieldName: string, value: string) => void };
    label: string;
    name?: string;
    onChange?: (name: string, value: string) => void;
    disabled?: boolean;
  }) => {
    const fieldName = name ?? field.name;
    return (
      <label>
        {label}
        <input
          aria-label={label}
          disabled={disabled}
          value={form.values[fieldName] ?? ''}
          onChange={(event) => {
            form.setFieldValue(fieldName, event.currentTarget.value);
            onChange?.(fieldName, event.currentTarget.value);
          }}
        />
      </label>
    );
  },
}));

vi.mock('../../../../components/Accordion', () => ({
  Accordion: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AccordionSummary: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('@components/common/entreprise_edition/EnterpriseEditionButton', () => ({
  __esModule: true,
  default: ({ title }: { title: string }) => <button type="button">{title}</button>,
}));

const connectorFixture: IngestionConnector = {
  title: 'CrowdStrike Falcon Intel',
  slug: 'crowdstrike-falcon-intel',
  description: 'Connector description',
  short_description: 'Short description',
  logo: 'https://example.com/logo.png',
  use_cases: [],
  solution_categories: [],
  license_type: 'Commercial',
  verified: true,
  last_verified_date: '2026-09-21',
  playbook_supported: false,
  max_confidence_level: 50,
  support_version: '1.0.0',
  subscription_link: 'https://example.com/subscription',
  source_code: 'https://example.com/source',
  manager_supported: true,
  container_version: '1.0.0',
  container_image: 'registry.example.com/crowdstrike-falcon-intel:latest',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://example.com/schema',
    type: 'object',
    properties: {},
    required: [],
    additionalProperties: false,
  },
};

describe('IngestionCatalogConnectorCreation', () => {
  const renderComponent = (isEnterpriseEdition: boolean) => testRender(
    <IngestionCatalogConnectorCreation
      connector={connectorFixture}
      open
      onClose={vi.fn()}
      catalogId="catalog-1"
      isEnterpriseEdition={isEnterpriseEdition}
      hasActiveManagers
    />,
  );

  it('shows the EE upsell with a Create label in CE', () => {
    renderComponent(false);

    expect(screen.getByText('Connector deployment requires OpenCTI Enterprise Edition. This configuration is read-only in Community Edition.')).toBeInTheDocument();
    expect(screen.getByLabelText('Display name')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
  });

  it('shows the Create action in EE', () => {
    renderComponent(true);

    expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
  });
});
