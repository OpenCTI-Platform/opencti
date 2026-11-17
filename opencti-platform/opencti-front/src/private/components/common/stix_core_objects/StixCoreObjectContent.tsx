import React, { ChangeEvent, FunctionComponent, useEffect, useRef, useState } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { useLocation, useNavigate } from 'react-router';
import { styled } from '@mui/material/styles';
import TextField from '@mui/material/TextField';
import { Document, Page } from 'react-pdf';
import 'react-pdf/dist/Page/TextLayer.css';
import 'react-pdf/dist/Page/AnnotationLayer.css';
import ReactMde from 'react-mde';
import { interval, Subscription } from 'rxjs';
import { RichTextEditor } from '@filigran/rich-text-editor';
import { ContainerMappingContent_container$data } from '@components/common/containers/__generated__/ContainerMappingContent_container.graphql';
import StixCoreObjectMappableContent from './StixCoreObjectMappableContent';
import TextFieldAskAI from '../form/TextFieldAskAI';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectContentFiles, { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from './StixCoreObjectContentFiles';
import { APP_BASE_PATH, commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectContentBar from './StixCoreObjectContentBar';
import { isEmptyField } from '../../../../utils/utils';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { htmlToPdf } from '../../../../utils/htmlToPdf/htmlToPdf';
import HtmlDisplay from '../../../../components/HtmlDisplay';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { isPdfPasswordError } from './StixCoreObjectContentPdfUtils';
import {
  filterContentTabFiles,
  isContainerWithContent,
  isContentTabImage,
  isPreviewOnlyFile,
  resolveContentFileMimeType,
} from './StixCoreObjectContentFileUtils';
import StixCoreObjectContentImageViewer from './StixCoreObjectContentImageViewer';
import { StixCoreObjectContent_stixCoreObject$data } from './__generated__/StixCoreObjectContent_stixCoreObject.graphql';

import '../../../../utils/pdfWorker-setup';

type ContentMode = 'content' | 'editor' | 'mapping';
type MarkdownTab = 'write' | 'preview';

type StixCoreObjectData = StixCoreObjectContent_stixCoreObject$data;
type ImportFile = NonNullable<StixCoreObjectData['importFiles']>['edges'][number]['node'];
type ExportFile = NonNullable<StixCoreObjectData['exportFiles']>['edges'][number]['node'];
type TemplateFile = NonNullable<StixCoreObjectData['filesFromTemplate']>['edges'][number]['node'];
type ExternalReferenceFile = NonNullable<StixCoreObjectData['externalReferences']>['edges'][number]['node']['importFiles']['edges'][number]['node'];

// Common shape of every file the Content tab can select, whatever its origin
interface ContentFile {
  id: string;
  name: string;
  uploadStatus?: string;
  metaData?: {
    mimetype?: string | null;
    file_markings?: ReadonlyArray<string | null | undefined> | null;
  } | null;
}

interface NavOpenProps {
  navOpen: boolean;
}

const Container = styled('div')(({ theme }) => ({
  width: '100%',
  height: '100%',
  marginTop: theme.spacing(1),
}));

const DocumentContainer = styled('div', {
  shouldForwardProp: (prop) => prop !== 'navOpen',
})<NavOpenProps>(({ navOpen }) => ({
  margin: '5px 0 0 0',
  overflow: 'scroll',
  whiteSpace: 'nowrap',
  minWidth: navOpen ? 'calc(100vw - 580px)' : 'calc(100vw - 455px)',
  minHeight: 'calc(100vh - 310px)',
  width: navOpen ? 'calc(100vw - 580px)' : 'calc(100vw - 455px)',
  height: 'calc(100vh - 310px)',
  maxWidth: navOpen ? 'calc(100vw - 580px)' : 'calc(100vw - 455px)',
  maxHeight: 'calc(100vh - 310px)',
  display: 'flex',
  justifyContent: 'center',
}));

// Block layout (not flex centring): a zoomed image wider than the panel must stay reachable by scrolling on both sides
const ImageContainer = styled(DocumentContainer)({
  display: 'block',
  textAlign: 'center',
});

const AdjustedContainer = styled('div', {
  shouldForwardProp: (prop) => prop !== 'navOpen',
})<NavOpenProps>(({ navOpen }) => ({
  margin: '5px 0 0 0',
  overflow: 'hidden',
  whiteSpace: 'nowrap',
  minWidth: navOpen ? 'calc(100vw - 590px)' : 'calc(100vw - 465px)',
  minHeight: 'calc(100vh - 310px)',
  width: navOpen ? 'calc(100vw - 590px)' : 'calc(100vw - 465px)',
  height: 'calc(100vh - 310px)',
  maxWidth: navOpen ? 'calc(100vw - 590px)' : 'calc(100vw - 465px)',
  maxHeight: 'calc(100vh - 310px)',
  display: 'flex',
  justifyContent: 'center',
  position: 'relative',
}));

const DocumentContainerWithoutBar = styled('div', {
  shouldForwardProp: (prop) => prop !== 'navOpen',
})<NavOpenProps>(({ navOpen }) => ({
  margin: 0,
  overflow: 'scroll',
  minWidth: navOpen ? 'calc(100vw - 580px)' : 'calc(100vw - 455px)',
  minHeight: 'calc(100vh - 260px)',
  width: navOpen ? 'calc(100vw - 580px)' : 'calc(100vw - 455px)',
  height: 'calc(100vh - 260px)',
  maxWidth: navOpen ? 'calc(100vw - 580px)' : 'calc(100vw - 455px)',
  maxHeight: 'calc(100vh - 260px)',
}));

const EditorContainer = styled('div')(({ theme }) => ({
  height: '100%',
  minHeight: '100%',
  padding: `0 0 ${theme.spacing(2)} 0`,
  borderRadius: 4,
  position: 'relative',
}));

const HtmlEditorContainer = styled(EditorContainer)({
  '& .MuiToggleButtonGroup-root.MuiToggleButtonGroup-horizontal': {
    // reduce gap between buttons in the toolbar to let space for the AI button
    gap: 0,
  },
});

const EditorContainerPreview = styled('div')({
  overflowY: 'scroll',
  overflowX: 'hidden',
});

const interval$ = interval(FIVE_SECONDS);

const stixCoreObjectContentUploadExternalReferenceMutation = graphql`
  mutation StixCoreObjectContentUploadExternalReferenceMutation(
    $id: ID!
    $file: Upload!
    $fileMarkings: [String]
  ) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, noTriggerImport: true, fileMarkings: $fileMarkings) {
        id
        name
        uploadStatus
        lastModified
        lastModifiedSinceMin
        metaData {
          mimetype
          list_filters
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
        }
        metaData {
          mimetype
        }
      }
    }
  }
`;

// Oldest first, same order as the Files section (stable sort, files with the same date keep their order)
const sortByLastModified = <T extends { lastModified?: string | null }>(files: T[]): T[] => {
  return [...files].sort((a, b) => {
    const aDate = a.lastModified ?? '';
    const bDate = b.lastModified ?? '';
    if (aDate < bDate) return -1;
    return aDate > bDate ? 1 : 0;
  });
};

const getFiles = (stixCoreObject: StixCoreObjectData): (ImportFile | ExternalReferenceFile)[] => {
  const importFiles = stixCoreObject.importFiles?.edges
    ?.filter((n) => !!n?.node)
    .map((n) => n.node) ?? [];
  const externalReferencesFiles = stixCoreObject.externalReferences?.edges
    ?.map((n) => n?.node?.importFiles?.edges)
    .flat()
    .filter((n) => !!n?.node)
    .map((n) => n.node)
    .filter(
      (n) => n.metaData && isEmptyField(n.metaData.external_reference_id),
    ) ?? [];
  return filterContentTabFiles<ImportFile | ExternalReferenceFile>([...importFiles, ...externalReferencesFiles]);
};

const getFilesFromTemplate = (stixCoreObject: StixCoreObjectData): TemplateFile[] => {
  const filesFromTemplate = stixCoreObject.filesFromTemplate?.edges
    ?.filter((n) => !!n?.node)
    .map((n) => n.node) ?? [];
  return sortByLastModified([...filesFromTemplate]);
};

const getExportFiles = (stixCoreObject: StixCoreObjectData): ExportFile[] => {
  const exportFiles = stixCoreObject.exportFiles?.edges
    ?.filter((n) => !!n?.node)
    .map((n) => n.node) ?? [];
  return sortByLastModified(
    [...exportFiles].filter((n) => {
      return (
        n.metaData?.mimetype === 'application/pdf'
        || n.uploadStatus === 'progress'
      );
    }),
  );
};

const getAllFiles = (stixCoreObject: StixCoreObjectData): ContentFile[] => [
  ...getFiles(stixCoreObject),
  ...getExportFiles(stixCoreObject),
  ...getFilesFromTemplate(stixCoreObject),
];

interface StixCoreObjectContentComponentProps {
  stixCoreObject: StixCoreObjectData;
  relay: RelayRefetchProp;
  currentMode: ContentMode;
  setMappingHeaderDisabled: (disabled: boolean) => void;
  setEditorHeaderDisabled: (disabled: boolean) => void;
}

// View parameters read back from the URL and the saved view
interface ContentViewParams {
  currentFileId?: string | null;
  contentSelected?: boolean;
  forceFile?: boolean;
}

// View parameters written to the URL and the saved view
interface SavedContentView {
  currentFileId: string | null | undefined;
  contentSelected: boolean;
  pdfViewerZoom: number;
}

interface InitialContentState {
  currentFileId: string | null | undefined;
  contentSelected: boolean;
  isLoading: boolean;
  onProgressExportFileName: string | undefined;
}

// Selection to restore on mount: from the URL / saved view, else the content of the container, else the first file
const getInitialContentState = (stixCoreObject: StixCoreObjectData, params: ContentViewParams): InitialContentState => {
  const isContentCompatible = isContainerWithContent(stixCoreObject.entity_type);
  const files = getFiles(stixCoreObject);
  const exportFiles = getExportFiles(stixCoreObject);
  let currentFileId: string | null | undefined = isEmptyField(stixCoreObject.contentField) ? files[0]?.id : null;
  let isLoading = false;
  let onProgressExportFileName: string | undefined;
  if (params.currentFileId && (!params.contentSelected || params.forceFile)) {
    const onProgressExportFile = exportFiles.find(
      (file) => file.id === params.currentFileId && file.uploadStatus === 'progress',
    );
    if (onProgressExportFile) {
      isLoading = true;
      onProgressExportFileName = onProgressExportFile.name;
    }
    currentFileId = params.currentFileId;
  }
  return {
    currentFileId: isContentCompatible && params.contentSelected && params.forceFile !== true ? null : currentFileId,
    contentSelected: !!(isContentCompatible && params.forceFile !== true && (params.contentSelected || isEmptyField(currentFileId))),
    isLoading,
    onProgressExportFileName,
  };
};

const StixCoreObjectContentComponent: FunctionComponent<StixCoreObjectContentComponentProps> = ({
  stixCoreObject,
  relay,
  currentMode,
  setMappingHeaderDisabled,
  setEditorHeaderDisabled,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const location = useLocation();
  const { typesWithFintelTemplates } = useAttributes();

  const localStorageKey = `stix-core-object-content-${stixCoreObject.id}`;
  const isContentCompatible = isContainerWithContent(stixCoreObject.entity_type);
  const defaultContent = isContentCompatible ? stixCoreObject.contentField : t_i18n('Write something awesome...');

  // Read the URL and the saved view once, on mount
  const [initialState] = useState(() => getInitialContentState(
    stixCoreObject,
    buildViewParamsFromUrlAndStorage(navigate, location, localStorageKey),
  ));
  const [currentFileId, setCurrentFileId] = useState(initialState.currentFileId);
  const [contentSelected, setContentSelected] = useState(initialState.contentSelected);
  const [isLoading, setIsLoading] = useState(initialState.isLoading);
  const [onProgressExportFileName, setOnProgressExportFileName] = useState(initialState.onProgressExportFileName);
  const [totalPdfPageNumber, setTotalPdfPageNumber] = useState<number | null>(null);
  const [pdfViewerZoom, setPdfViewerZoom] = useState(1.2);
  const [markdownSelectedTab, setMarkdownSelectedTab] = useState<MarkdownTab>('write');
  const [currentContent, setCurrentContent] = useState<string | null | undefined>(defaultContent);
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');
  const [changed, setChanged] = useState(false);
  const [blockedPdfPreviewFileId, setBlockedPdfPreviewFileId] = useState<string | null | undefined>(null);

  // Periodic refetch, stopped once an export opened from the URL has completed
  const refetchSubscription = useRef<Subscription | undefined>(undefined);

  const saveView = (view: Partial<SavedContentView>) => {
    const savedView: SavedContentView = { currentFileId, contentSelected, pdfViewerZoom, ...view };
    saveViewParameters(navigate, location, localStorageKey, savedView);
  };

  const loadFileContent = async (fileId: string | null | undefined) => {
    setIsLoading(true);
    if (!fileId) {
      setIsLoading(false);
      return;
    }
    const currentFile = getAllFiles(stixCoreObject).find((f) => f.id === fileId);
    // A file just uploaded is not listed until the refetch completes: guess its type from its name
    const fileType = resolveContentFileMimeType(fileId, currentFile?.metaData?.mimetype);
    if (isPreviewOnlyFile(fileType)) {
      setEditorHeaderDisabled(true);
      setIsLoading(false);
      return;
    }
    setEditorHeaderDisabled(false);
    const res = await fetch(`${APP_BASE_PATH}/storage/view/${encodeURIComponent(fileId)}`);
    if (!res.ok) throw new Error(`Failed to fetch file content: ${res.status}`);
    setCurrentContent(await res.text());
    setIsLoading(false);
  };

  const handleSelectFile = (fileId: string) => {
    setCurrentFileId(fileId);
    setChanged(false);
    setContentSelected(false);
    setBlockedPdfPreviewFileId(null);
    setMappingHeaderDisabled(true);
    loadFileContent(fileId);
    saveView({ currentFileId: fileId, contentSelected: false });
  };

  useEffect(() => {
    const toggleSubscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    refetchSubscription.current = interval$.subscribe(() => {
      relay.refetch({ id: stixCoreObject.id });
    });
    const initialFile = getAllFiles(stixCoreObject).find((f) => f.id === initialState.currentFileId);
    if (initialFile?.uploadStatus !== 'progress') {
      loadFileContent(initialState.currentFileId);
    }
    return () => {
      toggleSubscription.unsubscribe();
      refetchSubscription.current?.unsubscribe();
    };
  }, []);

  // An export opened from the URL while still generating: select it as soon as it is complete
  useEffect(() => {
    if (!onProgressExportFileName) return;
    const exportFile = getExportFiles(stixCoreObject).find((file) => file.name === onProgressExportFileName);
    if (exportFile?.uploadStatus === 'complete') {
      handleSelectFile(exportFile.id);
      setOnProgressExportFileName(undefined);
      refetchSubscription.current?.unsubscribe();
    }
  }, [stixCoreObject, onProgressExportFileName]);

  const handleSelectContent = () => {
    setCurrentFileId(null);
    setChanged(false);
    setContentSelected(true);
    setBlockedPdfPreviewFileId(null);
    setCurrentContent(stixCoreObject.contentField ?? t_i18n('Write something awesome...'));
    setMappingHeaderDisabled(false);
    setEditorHeaderDisabled(false);
    saveView({ currentFileId: null, contentSelected: true });
  };

  const handleFileChange = (fileName?: string, isDelete = false) => {
    relay.refetch({ id: stixCoreObject.id });
    if (fileName && fileName === currentFileId && isDelete) {
      setMappingHeaderDisabled(false);
      setEditorHeaderDisabled(false);
      setCurrentFileId(null);
      setContentSelected(isContentCompatible);
      setBlockedPdfPreviewFileId(null);
      setCurrentContent(isContentCompatible ? stixCoreObject.contentField ?? t_i18n('Write something awesome...') : '');
      saveView({ currentFileId: null, contentSelected: isContentCompatible });
    } else if (fileName && !isDelete) {
      setCurrentFileId(fileName);
      setContentSelected(false);
      setBlockedPdfPreviewFileId(null);
      loadFileContent(fileName);
      saveView({ currentFileId: fileName, contentSelected: false });
    }
  };

  const handlePdfLoadError = (error: Error) => {
    if (!isPdfPasswordError(error)) {
      return;
    }
    setBlockedPdfPreviewFileId(currentFileId);
  };

  const handlePdfPasswordRequest = (updatePassword: (password: string) => void) => {
    const password = window.prompt(t_i18n('This PDF is password protected. Enter password to preview it.'));
    if (password === null) {
      setBlockedPdfPreviewFileId(currentFileId);
      return;
    }
    updatePassword(password);
  };

  const onDocumentLoadSuccess = ({ numPages }: { numPages: number }) => {
    setTotalPdfPageNumber(numPages);
  };

  const handleZoomIn = () => {
    const zoom = pdfViewerZoom + 0.2;
    setPdfViewerZoom(zoom);
    saveView({ pdfViewerZoom: zoom });
  };

  const handleZoomOut = () => {
    const zoom = pdfViewerZoom - 0.2;
    setPdfViewerZoom(zoom);
    saveView({ pdfViewerZoom: zoom });
  };

  const prepareSaveFile = () => {
    if (!currentFileId) return null;
    const editableFiles: ContentFile[] = [...getFiles(stixCoreObject), ...getFilesFromTemplate(stixCoreObject)];
    const fileToSave = editableFiles.find((n) => n.id === currentFileId);
    if (!fileToSave) return null;
    const fileType = fileToSave.metaData?.mimetype ?? undefined;
    const fragment = currentFileId.split('/');
    const currentName = fragment[fragment.length - 1];
    const currentId = fragment[fragment.length - 2];
    const currentType = fragment[fragment.length - 3];
    const isExternalReference = currentType === 'External-Reference';
    const blob = new Blob([currentContent ?? ''], { type: fileType });
    const file = new File([blob], currentName, { type: fileType });
    return { currentId, isExternalReference, file, fileToSave };
  };

  const saveFile = () => {
    const prepared = prepareSaveFile();
    if (!prepared) return;
    const { currentId, isExternalReference, file, fileToSave } = prepared;
    commitMutation({
      mutation: isExternalReference
        ? stixCoreObjectContentUploadExternalReferenceMutation
        : stixCoreObjectContentFilesUploadStixCoreObjectMutation,
      variables: {
        file,
        id: currentId,
        noTriggerImport: true,
        fileMarkings: fileToSave.metaData?.file_markings,
        fromTemplate: fileToSave.id.startsWith('fromTemplate/'),
      },
      onCompleted: () => setChanged(false),
    });
  };

  const onTextFieldChange = (event: { target: { value: string } }) => {
    setCurrentContent(event.target.value);
    setChanged(true);
  };

  const onHtmlFieldChange = (content: string) => {
    setCurrentContent(content);
  };

  const onMarkDownFieldChange = (value: string) => {
    setCurrentContent(value);
    setChanged(true);
  };

  const onMarkdownChangeTab = (tab: MarkdownTab) => {
    setMarkdownSelectedTab(tab);
  };

  const handleDownloadMappableContentInPdf = async () => {
    const regex = /<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi;
    const htmlData = (currentContent ?? '')
      .replaceAll('id="undefined" ', '')
      .replaceAll(regex, '');
    const fragment = (stixCoreObject.name ?? '').split('/');
    const currentName = fragment[fragment.length - 1];
    await htmlToPdf('content', htmlData).download(`${currentName}.pdf`);
  };

  const files = getFiles(stixCoreObject);
  const exportFiles = getExportFiles(stixCoreObject);
  const filesFromTemplate = getFilesFromTemplate(stixCoreObject);
  const currentUrl = currentFileId
    ? `${APP_BASE_PATH}/storage/view/${encodeURIComponent(currentFileId)}`
    : undefined;
  const currentFile: ContentFile | undefined = currentFileId
    ? [...files, ...exportFiles, ...filesFromTemplate].find((n) => n.id === currentFileId)
    : undefined;
  const currentFileType = currentFile?.metaData?.mimetype;
  const isBlockedPdfPreview = currentFileType === 'application/pdf' && currentFileId === blockedPdfPreviewFileId;
  const height = window.innerHeight - 320;
  const hasFintelTemplates = (typesWithFintelTemplates ?? []).includes(stixCoreObject.entity_type);

  return (
    <Container data-testid="sco-content-page">
      <StixCoreObjectContentFiles
        stixCoreObjectId={stixCoreObject.id}
        stixCoreObjectName={stixCoreObject.name ?? ''}
        stixCoreObjectType={stixCoreObject.entity_type}
        content={isContentCompatible ? stixCoreObject.contentField ?? '' : null}
        contentSelected={contentSelected}
        // External reference files have no markings: the list renders them without
        files={files as ImportFile[]}
        exportFiles={exportFiles}
        handleSelectContent={handleSelectContent}
        handleSelectFile={handleSelectFile}
        currentFileId={currentFileId ?? ''}
        onFileChange={handleFileChange}
        filesFromTemplate={filesFromTemplate}
        hasOutcomesTemplate={isContentCompatible || hasFintelTemplates}
      />
      {isLoading ? (
        <Loader variant={LoaderVariant.inElement} />
      ) : (
        <>
          {contentSelected && (
            <StixCoreObjectMappableContent
              // The fragment holds every field the mappable content reads, under its own fragment type
              containerData={stixCoreObject as unknown as ContainerMappingContent_container$data}
              handleDownloadPdf={handleDownloadMappableContentInPdf}
              askAi={true}
              editionMode={true}
              currentMode={currentMode}
            />
          )}
          {currentFileType === 'text/plain' && currentMode === 'content' && (
            <>
              <DocumentContainerWithoutBar navOpen={navOpen}>
                {currentContent}
              </DocumentContainerWithoutBar>
            </>
          )}
          {currentFileType === 'text/plain' && currentMode === 'editor' && (
            <>
              <StixCoreObjectContentBar
                navOpen={navOpen}
                handleSave={saveFile}
                changed={changed}
              />
              <EditorContainer
                style={{ minHeight: height }}
              >
                <TextField
                  rows={Math.round(height / 23)}
                  key={currentFile?.id}
                  id={currentFile?.id}
                  value={currentContent ?? ''}
                  multiline={true}
                  onChange={(event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onTextFieldChange(event)}
                  fullWidth={true}
                  slotProps={{
                    input: {
                      endAdornment: (
                        <TextFieldAskAI
                          currentValue={currentContent ?? ''}
                          setFieldValue={(val) => {
                            onTextFieldChange({ target: { value: val } });
                          }}
                          format="text"
                          variant="text"
                        />
                      ),
                    },
                  }}
                />
              </EditorContainer>
            </>
          )}
          {currentFileType === 'text/html' && currentMode === 'content' && (
            <DocumentContainerWithoutBar navOpen={navOpen}>
              <HtmlDisplay content={currentContent ?? null} />
            </DocumentContainerWithoutBar>
          )}
          {currentFileType === 'text/html' && currentMode === 'editor' && (
            <>
              <StixCoreObjectContentBar
                handleSave={saveFile}
                changed={changed}
                navOpen={navOpen}
              />
              <HtmlEditorContainer
                style={{ minHeight: height, height }}
              >
                <RichTextEditor
                  data={currentContent ?? ''}
                  onChange={(_, adapter) => {
                    setCurrentContent(adapter.getData());
                      setChanged(true);
                  }}
                  onBlur={(_, adapter) => {
                    onHtmlFieldChange(adapter.getData());
                  }}
                />
                <TextFieldAskAI
                  currentValue={currentContent ?? ''}
                  setFieldValue={(val) => {
                    onHtmlFieldChange(val);
                  }}
                  format="html"
                  variant="html"
                  style={{ position: 'absolute', top: 10, right: 0 }}
                />
              </HtmlEditorContainer>
            </>
          )}
          {currentFileType === 'text/markdown' && currentMode === 'content' && (
            <DocumentContainerWithoutBar navOpen={navOpen}>
              <MarkdownDisplay
                content={currentContent}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </DocumentContainerWithoutBar>
          )}
          {currentFileType === 'text/markdown' && currentMode === 'editor' && (
            <>
              <StixCoreObjectContentBar
                navOpen={navOpen}
                handleSave={saveFile}
                changed={changed}
              />
              <EditorContainer
                style={{ minHeight: height, height }}
              >
                <ReactMde
                  value={currentContent ?? ''}
                  minEditorHeight={height - 80}
                  maxEditorHeight={height - 80}
                  onChange={onMarkDownFieldChange}
                  selectedTab={markdownSelectedTab}
                  onTabChange={onMarkdownChangeTab}
                  generateMarkdownPreview={(markdown) => Promise.resolve(
                    <EditorContainerPreview style={{ height: height - 80, maxHeight: height - 80 }}>
                      <MarkdownDisplay
                        content={markdown}
                        remarkGfmPlugin={true}
                        commonmark={true}
                      />
                    </EditorContainerPreview>,
                  )
                  }
                  l18n={{
                    write: t_i18n('Write'),
                    preview: t_i18n('Preview'),
                    uploadingImage: t_i18n('Uploading image'),
                    pasteDropSelect: t_i18n('Paste'),
                  }}
                />
                <TextFieldAskAI
                  currentValue={currentContent ?? ''}
                  setFieldValue={(val) => {
                    onMarkDownFieldChange(val);
                  }}
                  format="markdown"
                  variant="markdown"
                />
              </EditorContainer>
            </>
          )}
          {currentFileType === 'application/pdf' && !isBlockedPdfPreview && (
            <>
              <StixCoreObjectContentBar
                handleZoomIn={handleZoomIn}
                handleZoomOut={handleZoomOut}
                currentZoom={pdfViewerZoom}
                navOpen={navOpen}
              />
              <DocumentContainer navOpen={navOpen}>
                <Document
                  suspense={false}
                  onLoadSuccess={onDocumentLoadSuccess}
                  onLoadError={handlePdfLoadError}
                  onPassword={handlePdfPasswordRequest}
                  loading={<Loader variant={LoaderVariant.inElement} />}
                  file={currentUrl}
                >
                  {Array.from(new Array(totalPdfPageNumber), (_el, index) => (
                    <Page
                      key={`page_${index + 1}`}
                      pageNumber={index + 1}
                      height={height}
                      scale={pdfViewerZoom}
                    />
                  ))}
                </Document>
              </DocumentContainer>
            </>
          )}
          {currentFile && isContentTabImage(currentFileType) && (
            <>
              <StixCoreObjectContentBar
                handleZoomIn={handleZoomIn}
                handleZoomOut={handleZoomOut}
                currentZoom={pdfViewerZoom}
                navOpen={navOpen}
              />
              <ImageContainer navOpen={navOpen}>
                <StixCoreObjectContentImageViewer
                  key={currentFile.id}
                  fileId={currentFile.id}
                  fileName={currentFile.name}
                  height={height}
                  zoom={pdfViewerZoom}
                />
              </ImageContainer>
            </>
          )}
          {isBlockedPdfPreview && (
            <AdjustedContainer navOpen={navOpen}>
              <div
                style={{
                  display: 'table',
                  height: '100%',
                  width: '100%',
                }}
              >
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t_i18n('Unable to preview this PDF. It may be password protected. Select another file to continue.')}
                </span>
              </div>
            </AdjustedContainer>
          )}
          {!currentFile && !contentSelected && (
            <AdjustedContainer navOpen={navOpen}>
              <div
                style={{
                  display: 'table',
                  height: '100%',
                  width: '100%',
                }}
              >
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t_i18n('No file selected.')}
                </span>
              </div>
            </AdjustedContainer>
          )}
        </>
      )}
    </Container>
  );
};

export const stixCoreObjectContentRefetchQuery = graphql`
  query StixCoreObjectContentRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...StixCoreObjectContent_stixCoreObject
    }
  }
`;

const StixCoreObjectContent = createRefetchContainer(
  StixCoreObjectContentComponent,
  {
    stixCoreObject: graphql`
      fragment StixCoreObjectContent_stixCoreObject on StixCoreObject {
        id
        entity_type
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        ... on Report {
          name
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Case {
          name
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Grouping {
          name
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        importFiles(first: 500) @connection(key: "Pagination_importFiles") {
          edges {
            node {
              id
              name
              uploadStatus
              lastModified
              lastModifiedSinceMin
              objectMarking {
                id
                x_opencti_color
                definition
              }
              metaData {
                mimetype
                list_filters
                file_markings
                messages {
                  timestamp
                  message
                }
                errors {
                  timestamp
                  message
                }
              }
              metaData {
                mimetype
              }
            }
          }
        }
        exportFiles(first: 500) @connection(key: "Pagination_exportFiles") {
          edges {
            node {
              id
              name
              uploadStatus
              lastModified
              lastModifiedSinceMin
              objectMarking {
                id
                x_opencti_color
                definition
              }
              metaData {
                mimetype
                file_markings
              }
              ...FileLine_file
            }
          }
        }
        ... on StixDomainObject {
          filesFromTemplate(first: 500) @connection(key: "Pagination_filesFromTemplate") {
            edges {
              node {
                id
                name
                uploadStatus
                lastModified
                lastModifiedSinceMin
                objectMarking {
                  id
                  x_opencti_color
                  definition
                }
                  metaData {
                    mimetype
                    list_filters
                    file_markings
                    messages {
                      timestamp
                      message
                    }
                    errors {
                      timestamp
                      message
                    }
                  }
                  metaData {
                    mimetype
                  }
              }
            }
          }
          fintelTemplates {
            id
            name
            default
            template_content
          }
        }
        externalReferences {
          edges {
            node {
              source_name
              url
              description
              importFiles(first: 500) {
                edges {
                  node {
                    id
                    name
                    uploadStatus
                    lastModified
                    lastModifiedSinceMin
                    metaData {
                      mimetype
                      list_filters
                      external_reference_id
                      messages {
                        timestamp
                        message
                      }
                      errors {
                        timestamp
                        message
                      }
                    }
                    metaData {
                      mimetype
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixCoreObjectContentRefetchQuery,
);

export default StixCoreObjectContent;
