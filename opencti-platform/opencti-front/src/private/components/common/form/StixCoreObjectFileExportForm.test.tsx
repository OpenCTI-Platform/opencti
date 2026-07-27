import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import StixCoreObjectFileExportForm, { ConnectorOption } from './StixCoreObjectFileExportForm';
import { BUILT_IN_FROM_TEMPLATE } from '../stix_core_objects/StixCoreObjectFileExport';

// Stub Relay-dependent sub-components
vi.mock('./ObjectMarkingField', () => ({ default: () => null }));
vi.mock('./FintelDesignField', () => ({ default: () => null }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../../../utils/hooks/useAI', () => ({ default: () => ({ enabled: false, configured: false }) }));

const templateConnector: ConnectorOption = {
  ...BUILT_IN_FROM_TEMPLATE,
  label: 'Generate FINTEL from template',
};

const templates = [
  { value: 'tpl-1', label: 'Template A', isDefault: false },
  { value: 'tpl-2', label: 'Template B', isDefault: true },
];

const baseProps = {
  isOpen: true,
  onClose: vi.fn(),
  onSubmit: vi.fn(),
  connectors: [templateConnector],
  handleOpenAskAi: vi.fn(),
};

describe('StixCoreObjectFileExportForm — default template pre-selection', () => {
  it('pre-selects the default template when defaultTemplate prop is provided', async () => {
    const defaultTemplate = { value: 'tpl-2', label: 'Template B', isDefault: true };

    testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        templates={templates}
        defaultTemplate={defaultTemplate}
        defaultValues={{ connector: BUILT_IN_FROM_TEMPLATE.value, format: 'application/pdf' }}
      />,
    );

    // format is pre-filled → goes directly to step 1 (form step)
    await waitFor(() => expect(screen.getByLabelText('Template')).toBeDefined());

    const templateInput = screen.getByLabelText('Template') as HTMLInputElement;
    expect(templateInput.value).toBe('Template B');
  });

  it('falls back to the first template when connector is fromTemplate but no default template exists', async () => {
    const templatesNoDefault = [
      { value: 'tpl-1', label: 'Template A', isDefault: false },
      { value: 'tpl-2', label: 'Template B', isDefault: false },
    ];

    testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        templates={templatesNoDefault}
        defaultTemplate={undefined}
        defaultValues={{ connector: BUILT_IN_FROM_TEMPLATE.value, format: 'application/pdf' }}
      />,
    );

    await waitFor(() => expect(screen.getByLabelText('Template')).toBeDefined());

    // Should fall back to templates[0]
    const templateInput = screen.getByLabelText('Template') as HTMLInputElement;
    expect(templateInput.value).toBe('Template A');
  });

  it('does not pre-select any template when template list is empty', async () => {
    testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        templates={[]}
        defaultTemplate={undefined}
        defaultValues={{ connector: BUILT_IN_FROM_TEMPLATE.value, format: 'application/pdf' }}
      />,
    );

    await waitFor(() => expect(screen.getByLabelText('Template')).toBeDefined());

    const templateInput = screen.getByLabelText('Template') as HTMLInputElement;
    expect(templateInput.value).toBe('');
  });
});
