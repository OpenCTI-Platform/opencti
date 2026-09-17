import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { MESSAGING$ } from '../../../../relay/environment';
import StixCoreObjectFileExport, { BUILT_IN_HTML_TO_PDF } from './StixCoreObjectFileExport';
import StixCoreObjectContentFiles from './StixCoreObjectContentFiles';

const { buildFileFromTemplate, htmlToPdfReport } = vi.hoisted(() => ({
  buildFileFromTemplate: vi.fn(),
  htmlToPdfReport: vi.fn(),
}));

vi.mock('../../../../utils/outcome_template/engine/useFileFromTemplate', () => ({
  default: () => ({ buildFileFromTemplate }),
}));
vi.mock('../../../../utils/htmlToPdf/htmlToPdf', () => ({ htmlToPdfReport, htmlToPdf: vi.fn() }));
vi.mock('../form/ObjectMarkingField', () => ({ default: () => null }));
vi.mock('../form/FintelDesignField', () => ({ default: () => null }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../../../utils/hooks/useAI', () => ({ default: () => ({ enabled: false, configured: false }) }));

const openExport = async (entityType = 'Report', fromContentShortcut = false) => {
  const onExportCompleted = vi.fn();
  const onClose = vi.fn();
  const result = testRender(
    fromContentShortcut ? (
      <StixCoreObjectContentFiles
        stixCoreObjectId="report-1"
        stixCoreObjectName="Test report"
        stixCoreObjectType={entityType}
        files={[]}
        exportFiles={[]}
        filesFromTemplate={[]}
        hasOutcomesTemplate={true}
        content={null}
        contentSelected={false}
        currentFileId=""
        handleSelectFile={vi.fn()}
        handleSelectContent={vi.fn()}
        onFileChange={onExportCompleted}
      />
    ) : (
      <StixCoreObjectFileExport
        scoId="report-1"
        scoEntityType={entityType}
        scoName="Test report"
        OpenFormComponent={({ onOpen }) => <button onClick={onOpen}>Export</button>}
        defaultValues={{ connector: BUILT_IN_HTML_TO_PDF.value, format: 'application/pdf' }}
        onExportCompleted={onExportCompleted}
        onClose={onClose}
      />
    ),
    { userContext: createMockUserContext({ me: { capabilities: [{ name: 'BYPASS' }] } }) },
  );
  await act(async () => {
    result.relayEnv.mock.resolveMostRecentOperation({
      data: {
        stixCoreObject: {
          __typename: entityType,
          __isStixDomainObject: entityType,
          ...(entityType === 'Report' ? { __isContainer: entityType } : {}),
          id: 'report-1',
          entity_type: entityType,
          representative: { main: 'Test report' },
          objectMarking: [],
          importFiles: { edges: [] },
          exportFiles: { edges: [] },
          filesFromTemplate: { edges: [] },
          fintelTemplates: [{ id: 'template-1', name: 'Briefing', default: true, includeCoverPageByDefault: false, includeBackPageByDefault: false }],
          content: '',
        },
        connectorsForExport: [],
      },
    });
  });
  await result.user.click(screen.getByRole('button', { name: fromContentShortcut ? 'Generate an export based on a template' : 'Export' }));
  if (fromContentShortcut) {
    expect(screen.getByLabelText('Export as fintel')).toBeChecked();
    expect(screen.getByLabelText('Template')).toHaveValue('');
    expect(screen.getByLabelText('File to export')).toBeDisabled();
  }
  await result.user.click(screen.getByLabelText('Template'));
  await result.user.click(await screen.findByRole('option', { name: 'Briefing' }));
  await result.user.type(screen.getByLabelText('Export file name'), 'briefing');
  await result.user.click(screen.getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(result.relayEnv.mock.getAllOperations()).toHaveLength(1));
  return { ...result, onExportCompleted, onClose };
};

const uploadResponse = (id: string, name: string, mimetype: string) => ({
  data: {
    stixCoreObjectEdit: {
      importPush: {
        id,
        name,
        uploadStatus: 'complete',
        lastModified: '2026-09-16T00:00:00.000Z',
        lastModifiedSinceMin: 0,
        metaData: { mimetype, fintel_template_id: 'template-1', list_filters: null, messages: [], errors: [] },
      },
    },
  },
});

describe('FINTEL HTML and PDF export', () => {
  beforeEach(() => {
    buildFileFromTemplate.mockReset().mockResolvedValue('<p>Generated briefing</p>');
    htmlToPdfReport.mockReset().mockResolvedValue({ getBlob: async () => new Blob(['PDF'], { type: 'application/pdf' }) });
  });

  it('opens PDF FINTEL generation directly from the Content Files shortcut', async () => {
    const { relayEnv, onExportCompleted } = await openExport('Report', true);
    expect(relayEnv.mock.getMostRecentOperation().request.variables.file.name).toBe('briefing.html');
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation(uploadResponse('html-1', 'briefing.html', 'text/html'));
    });
    await waitFor(() => expect(relayEnv.mock.getAllOperations()).toHaveLength(1));
    expect(relayEnv.mock.getMostRecentOperation().request.variables.file.name).toBe('briefing.pdf');
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation(uploadResponse('pdf-1', 'briefing.pdf', 'application/pdf'));
    });
    await waitFor(() => expect(onExportCompleted).toHaveBeenCalledWith('pdf-1'));
  });

  it.each(['Report', 'Vulnerability'])('saves HTML before rendering PDF and completes only after both uploads for %s', async (entityType) => {
    const { relayEnv, onExportCompleted, onClose } = await openExport(entityType);
    const htmlUpload = relayEnv.mock.getMostRecentOperation();
    expect(htmlUpload.request.variables).toMatchObject({
      id: 'report-1', fileMarkings: [], fromTemplate: true, fintelTemplateId: 'template-1',
    });
    expect(htmlUpload.request.variables.file.name).toBe('briefing.html');
    expect(htmlUpload.request.variables.file.type).toBe('text/html');
    expect(buildFileFromTemplate).toHaveBeenCalledWith('report-1', [], 'template-1');
    expect(htmlToPdfReport).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Create' })).toBeDisabled();

    await act(async () => {
      relayEnv.mock.resolve(htmlUpload, uploadResponse('html-1', 'briefing.html', 'text/html'));
    });
    await waitFor(() => expect(relayEnv.mock.getAllOperations()).toHaveLength(1));
    const pdfUpload = relayEnv.mock.getMostRecentOperation();
    expect(pdfUpload.request.variables.file.name).toBe('briefing.pdf');
    expect(pdfUpload.request.variables.file.type).toBe('application/pdf');
    expect(pdfUpload.request.variables).toMatchObject({ fileMarkings: [], fromTemplate: true, fintelTemplateId: 'template-1' });
    expect(htmlToPdfReport).toHaveBeenCalledWith(
      'Test report', '<p>Generated briefing</p>', 'Briefing', [],
      { file_id: null, gradiantFromColor: null, gradiantToColor: null, textColor: null },
      { includeCoverPage: true, includeBackPage: true },
    );
    expect(onClose).not.toHaveBeenCalled();
    expect(onExportCompleted).not.toHaveBeenCalled();

    await act(async () => {
      relayEnv.mock.resolve(pdfUpload, uploadResponse('pdf-1', 'briefing.pdf', 'application/pdf'));
    });
    await waitFor(() => expect(onExportCompleted).toHaveBeenCalledWith('pdf-1'));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('stops before PDF rendering when the HTML upload fails', async () => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError');
    const notifyRelayError = vi.spyOn(MESSAGING$, 'notifyRelayError');
    const { relayEnv, onExportCompleted, onClose } = await openExport();
    await act(async () => {
      relayEnv.mock.rejectMostRecentOperation(new Error('HTML upload failed'));
    });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create' })).not.toBeDisabled());
    expect(notifyError).toHaveBeenCalledExactlyOnceWith('Error trying to export the file');
    expect(notifyRelayError).not.toHaveBeenCalled();
    expect(htmlToPdfReport).not.toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.getByLabelText('Export file name')).toHaveValue('briefing');
    expect(onClose).not.toHaveBeenCalled();
    expect(onExportCompleted).not.toHaveBeenCalled();
  });

  it('does not dismiss an export while its upload is pending', async () => {
    const { onClose } = await openExport();
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape', code: 'Escape' });
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId('StixCoreObjectFileExportDialog')).toBeInTheDocument();
  });

  it.each(['render', 'upload'])('keeps the HTML and form when PDF %s fails', async (failureStage) => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError');
    const notifyRelayError = vi.spyOn(MESSAGING$, 'notifyRelayError');
    if (failureStage === 'render') htmlToPdfReport.mockRejectedValueOnce(new Error('PDF rendering failed'));
    const { relayEnv, onExportCompleted, onClose } = await openExport();
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation(uploadResponse('html-1', 'briefing.html', 'text/html'));
    });
    if (failureStage === 'upload') {
      await waitFor(() => expect(relayEnv.mock.getAllOperations()).toHaveLength(1));
      await act(async () => {
        relayEnv.mock.rejectMostRecentOperation(new Error('PDF upload failed'));
      });
    }
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create' })).not.toBeDisabled());
    expect(notifyError).toHaveBeenCalledExactlyOnceWith('The HTML file was saved, but the PDF export failed');
    expect(notifyRelayError).not.toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.getByLabelText('Export file name')).toHaveValue('briefing');
    expect(onClose).not.toHaveBeenCalled();
    expect(onExportCompleted).not.toHaveBeenCalled();
    notifyError.mockRestore();
  });
});
