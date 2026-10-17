import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import StixCoreObjectFileExportForm, { ConnectorOption, TemplateOption } from './StixCoreObjectFileExportForm';
import { BUILT_IN_FROM_TEMPLATE, BUILT_IN_HTML_TO_PDF } from '../stix_core_objects/StixCoreObjectFileExport';

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

describe('StixCoreObjectFileExportForm FINTEL PDF export', () => {
  const renderPdfForm = (availableTemplates: TemplateOption[] = templates, fileToExport?: string) => {
    const onSubmit = vi.fn();
    return {
      onSubmit,
      ...testRender(
        <StixCoreObjectFileExportForm
          {...baseProps}
          onSubmit={onSubmit}
          connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }]}
          templates={availableTemplates}
          defaultTemplate={availableTemplates[1]}
          defaultFileMarkings={[{ value: 'marking-1', label: 'TLP:GREEN' }]}
          fileOptions={[
            { value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] },
            { value: 'fromTemplate/file.html', label: 'Existing FINTEL', fileMarkings: [], fintelTemplateId: 'tpl-1' },
          ]}
          defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf', fileToExport }}
        />,
      ),
    };
  };

  it('starts in generation mode with the default template pre-selected, without inheriting file defaults', async () => {
    testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }]}
        templates={templates}
        defaultTemplate={templates[1]}
        fileOptions={[{ value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] }]}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
      />,
    );

    await waitFor(() => expect(screen.getByLabelText('Export as fintel')).toBeChecked());
    expect(screen.getByLabelText('Template')).toHaveValue('Template B');
    expect(screen.getByLabelText('File to export')).toBeDisabled();
    expect(screen.getByLabelText('File to export')).toHaveValue('Generated file');
    expect(screen.getByLabelText('Export file name')).toHaveValue('');
    expect(screen.getByLabelText('Remove empty sections')).not.toBeChecked();
    expect(screen.getByLabelText('Include cover page')).toBeChecked();
    expect(screen.getByLabelText('Include back page')).toBeChecked();
  });

  it('pre-selects the default template, requires a filename, and submits without inherited markings', async () => {
    const { user, onSubmit } = renderPdfForm();
    await waitFor(() => expect(screen.getByLabelText('Remove empty sections')).not.toBeChecked());
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(screen.getAllByText('This field is required')).toHaveLength(1));
    expect(onSubmit).not.toHaveBeenCalled();

    await user.click(screen.getByLabelText('Template'));
    await user.click(await screen.findByRole('option', { name: 'Template A' }));
    expect(screen.getByLabelText('Export file name')).toHaveValue('');
    await user.type(screen.getByLabelText('Export file name'), 'briefing');
    await user.click(screen.getByLabelText('Remove empty sections'));
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    expect(onSubmit.mock.calls[0][0]).toMatchObject({
      exportAsFintel: true,
      removeEmptySections: true,
      template: { value: 'tpl-1' },
      exportFileName: 'briefing',
      fileMarkings: [],
      contentMaxMarkings: [],
    });
  });

  it('defaults to existing-file export when a specific file is already targeted, but can still switch to template generation', async () => {
    const { user } = renderPdfForm(templates, 'mappableContent');
    expect(screen.queryByLabelText('Template')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Remove empty sections')).not.toBeInTheDocument();
    expect(screen.getByLabelText('File to export')).not.toBeDisabled();
    expect(screen.getByLabelText('File to export')).toHaveValue('Mappable main content');
    expect(screen.getByLabelText('Export file name')).not.toHaveValue('');

    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.getByLabelText('Template')).toBeInTheDocument());
    expect(screen.getByLabelText('File to export')).toBeDisabled();
    expect(screen.getByLabelText('Remove empty sections')).not.toBeChecked();

    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.queryByLabelText('Template')).not.toBeInTheDocument());
    expect(screen.queryByLabelText('Remove empty sections')).not.toBeInTheDocument();
    expect(screen.getByLabelText('File to export')).toHaveValue('Mappable main content');
  });

  it('keeps the same connector and falls back to a real file when the fintel toggle is switched off with no file preset', async () => {
    const onSubmit = vi.fn();
    const { user } = testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        onSubmit={onSubmit}
        connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }, templateConnector]}
        templates={templates}
        fileOptions={[{ value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] }]}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
      />,
    );
    await waitFor(() => expect(screen.getByLabelText('Export as fintel')).toBeChecked());

    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.getByLabelText('File to export')).toHaveValue('Mappable main content'));
    expect(screen.queryByLabelText('Template')).not.toBeInTheDocument();
    expect((screen.getByLabelText('Connector') as HTMLInputElement).value).toBe('HTML content files to PDF');
    await waitFor(() => expect(screen.getByLabelText('Export file name')).not.toHaveValue(''));

    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    expect(onSubmit.mock.calls[0][0]).toMatchObject({
      connector: { value: BUILT_IN_HTML_TO_PDF.value },
      fileToExport: { value: 'mappableContent' },
    });
  });

  it('keeps the legacy flow without available templates', async () => {
    renderPdfForm([]);
    await waitFor(() => expect(screen.getByLabelText('File to export')).toHaveValue('Mappable main content'));
    expect(screen.queryByLabelText('Export as fintel')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Template')).not.toBeInTheDocument();
    expect(screen.getByLabelText('File to export')).not.toBeDisabled();
    expect(screen.getByLabelText('Export file name')).not.toHaveValue('');
  });

  it.each([true, false])('restores entity markings when switching to the template connector with FINTEL %s', async (exportAsFintel) => {
    const onSubmit = vi.fn();
    const { user } = testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        onSubmit={onSubmit}
        connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }, templateConnector]}
        templates={templates}
        defaultTemplate={templates[1]}
        fileOptions={[{ value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] }]}
        defaultFileMarkings={[{ value: 'marking-1', label: 'TLP:GREEN' }]}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
      />,
    );
    if (!exportAsFintel) await user.click(screen.getByLabelText('Export as fintel'));
    await user.click(screen.getByLabelText('Connector'));
    await user.click(await screen.findByRole('option', { name: 'Generate FINTEL from template' }));
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    expect(onSubmit.mock.calls[0][0].fileMarkings).toEqual([{ value: 'marking-1', label: 'TLP:GREEN' }]);
    expect(onSubmit.mock.calls[0][0].exportAsFintel).toBe(exportAsFintel);
  });

  it.each([false, true])('forces HTML format and hides page options with the template connector (reselect PDF: %s)', async (reselectPdf) => {
    const onSubmit = vi.fn();
    const { user } = testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        onSubmit={onSubmit}
        connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }, templateConnector]}
        templates={templates}
        fileOptions={[{ value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] }]}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
      />,
    );

    await user.click(screen.getByLabelText('Connector'));
    await user.click(await screen.findByRole('option', { name: 'Generate FINTEL from template' }));

    if (reselectPdf) {
      await user.click(screen.getByRole('button', { name: 'Format' }));
      await user.click(screen.getByRole('button', { name: 'PDF' }));
    }

    // Page options (cover/back page) are PDF-only and must not show for the template-generated HTML export.
    await waitFor(() => expect(screen.queryByLabelText('Include cover page')).not.toBeInTheDocument());
    expect(screen.queryByLabelText('Include back page')).not.toBeInTheDocument();

    await user.click(screen.getByLabelText('Template'));
    await user.click(await screen.findByRole('option', { name: 'Template A' }));
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    expect(onSubmit.mock.calls[0][0]).toMatchObject({
      connector: { value: BUILT_IN_FROM_TEMPLATE.value },
      format: 'text/html',
    });
  });

  it('allows switching back to the HTML-to-PDF connector after selecting the template connector', async () => {
    const onSubmit = vi.fn();
    const { user } = testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        onSubmit={onSubmit}
        connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }, templateConnector]}
        templates={templates}
        fileOptions={[{ value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] }]}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
      />,
    );

    const connectorInput = () => screen.getByRole('combobox', { name: 'Connector' }) as HTMLInputElement;

    await user.click(connectorInput());
    await user.click(await screen.findByRole('option', { name: 'Generate FINTEL from template' }));
    expect(connectorInput().value).toBe('Generate FINTEL from template');

    await user.click(connectorInput());
    await user.click(await screen.findByRole('option', { name: 'HTML content files to PDF' }));

    await waitFor(() => expect(connectorInput().value).toBe('HTML content files to PDF'));
  });

  it('shows remove empty sections for template-generated modes only', async () => {
    const { user } = testRender(
      <StixCoreObjectFileExportForm
        {...baseProps}
        connectors={[{ ...BUILT_IN_HTML_TO_PDF, label: 'HTML content files to PDF' }, templateConnector]}
        templates={templates}
        fileOptions={[{ value: 'mappableContent', label: 'Mappable main content', fileMarkings: [] }]}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
      />,
    );

    await waitFor(() => expect(screen.getByLabelText('Remove empty sections')).toBeInTheDocument());
    expect(screen.getByLabelText('Remove empty sections')).not.toBeChecked();
    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.queryByLabelText('Remove empty sections')).not.toBeInTheDocument());
    await user.click(screen.getByLabelText('Connector'));
    await user.click(await screen.findByRole('option', { name: 'Generate FINTEL from template' }));
    await waitFor(() => expect(screen.getByLabelText('Remove empty sections')).toBeInTheDocument());
    expect(screen.getByLabelText('Remove empty sections')).not.toBeChecked();
  });

  it('restores the source template page defaults after switching back to legacy export', async () => {
    const { user } = renderPdfForm([
      { ...templates[0], include_cover_page_by_default: false, include_back_page_by_default: false },
    ], 'fromTemplate/file.html');
    // A specific FINTEL file is already targeted, so it starts in existing-file mode
    // and immediately reflects the origin template's page defaults.
    await waitFor(() => expect(screen.getByLabelText('Include cover page')).not.toBeChecked());
    expect(screen.getByLabelText('Include back page')).not.toBeChecked();

    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.getByLabelText('Include cover page')).toBeChecked());
    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.getByLabelText('Include cover page')).not.toBeChecked());
    await user.click(screen.getByLabelText('Export as fintel'));
    await waitFor(() => expect(screen.getByLabelText('Include cover page')).toBeChecked());
  });
});

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
