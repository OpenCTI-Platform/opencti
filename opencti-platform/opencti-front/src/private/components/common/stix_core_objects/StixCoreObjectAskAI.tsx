import React, { FunctionComponent, useState } from 'react';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { PopoverProps } from '@mui/material/Popover';
import { DialogTitle } from '@mui/material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import DialogActions from '@mui/material/DialogActions';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Radio from '@mui/material/Radio';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import { createSearchParams, useNavigate } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import {
  StixCoreObjectAskAISummarizeFilesMutation,
  StixCoreObjectAskAISummarizeFilesMutation$data,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectAskAISummarizeFilesMutation.graphql';
import { StixCoreObjectMappableContentFieldPatchMutation } from '@components/common/stix_core_objects/__generated__/StixCoreObjectMappableContentFieldPatchMutation.graphql';
import {
  StixCoreObjectAskAIContainerReportMutation,
  StixCoreObjectAskAIContainerReportMutation$data,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectAskAIContainerReportMutation.graphql';
import {
  StixCoreObjectAskAIConvertFilesToStixMutation,
  StixCoreObjectAskAIConvertFilesToStixMutation$data,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectAskAIConvertFilesToStixMutation.graphql';
import type {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
  StixCoreObjectContentFilesUploadStixCoreObjectMutation$data,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from './StixCoreObjectContentFiles';
import { stixCoreObjectMappableContentFieldPatchMutation } from './StixCoreObjectMappableContent';
import FilesNativeField from '../form/FilesNativeField';
import { useFormatter } from '../../../../components/i18n';
import ResponseDialog from '../../../../utils/ai/ResponseDialog';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAI from '../../../../utils/hooks/useAI';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { resolveLink } from '../../../../utils/Entity';
import useGranted, { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';

// region types
interface StixCoreObjectAskAiProps {
  instanceId: string;
  instanceName: string;
  instanceType: string;
  instanceMarkings?: string[];
  type: 'container' | 'threat' | 'victim' | 'unsupported';
}

const isContainerWithContent = (type: string) => ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].includes(type);

const stixCoreObjectAskAIContainerReportMutation = graphql`
  mutation StixCoreObjectAskAIContainerReportMutation($id: ID!, $containerId: String!, $paragraphs: Int, $tone: Tone, $format: Format) {
    aiContainerGenerateReport(id: $id, containerId: $containerId, paragraphs: $paragraphs, tone: $tone, format: $format)
  }
`;

const stixCoreObjectAskAISummarizeFilesMutation = graphql`
  mutation StixCoreObjectAskAISummarizeFilesMutation($id: ID!, $elementId: String!, $paragraphs: Int, $tone: Tone, $format: Format, $fileIds: [String]) {
    aiSummarizeFiles(id: $id, elementId: $elementId, paragraphs: $paragraphs, tone: $tone, format: $format, fileIds: $fileIds)
  }
`;

const stixCoreObjectAskAIConvertFilesToStixMutation = graphql`
  mutation StixCoreObjectAskAIConvertFilesToStixMutation($id: ID!, $elementId: String!, $fileIds: [String]) {
    aiConvertFilesToStix(id: $id, elementId: $elementId, fileIds: $fileIds)
  }
`;

const actionsOptions = {
  'container-report': ['format', 'paragraphs', 'tone'],
  'summarize-files': ['format', 'paragraphs', 'tone', 'files'],
  'convert-files': ['format', 'files'],
};

const actionsFormat = {
  'container-report': ['html', 'markdown', 'text'],
  'summarize-files': ['html', 'markdown', 'text'],
  'convert-files': ['json'],
};

const actionsExplanation = {
  'container-report': 'Generate a text report based on the knowledge graph (entities and relationships) of this container.',
  'summarize-files': 'Generate a summary of the selected files (or all files associated to this entity).',
  'convert-files': 'Try to convert the selected files (or all files associated to this entity) in a STIX 2.1 bundle.',
};

const StixCoreObjectAskAI: FunctionComponent<StixCoreObjectAskAiProps> = ({ instanceId, instanceType, instanceName, type, instanceMarkings }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured } = useAI();
  const isKnowledgeUploader = useGranted([KNOWLEDGE_KNUPLOAD]);
  const [action, setAction] = useState<'container-report' | 'summarize-files' | 'convert-files' | null>(null);
  const [content, setContent] = useState('');
  const [acceptedResult, setAcceptedResult] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [destination, setDestination] = useState<'content' | 'file'>('content');
  const [newFileName, setNewFileName] = useState<string | null>(null);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [tone, setTone] = useState<'tactical' | 'operational' | 'strategic'>('tactical');
  const [format, setFormat] = useState<'html' | 'markdown' | 'text' | 'json'>('html');
  const [paragraphs, setParagraphs] = useState(10);
  const [files, setFiles] = useState<{ label: string, value: string }[]>([]);
  const [disableResponse, setDisableResponse] = useState(false);
  const [menuOpen, setMenuOpen] = useState<{ open: boolean; anchorEl: PopoverProps['anchorEl'] }>({ open: false, anchorEl: null });
  const [busId, setBusId] = useState<string | null>(null);
  const [displayAskAI, setDisplayAskAI] = useState(false);
  const handleOpenMenu = (event: React.SyntheticEvent) => {
    if (isEnterpriseEdition) {
      event.preventDefault();
      setMenuOpen({ open: true, anchorEl: event.currentTarget });
    }
  };
  const handleCloseMenu = () => {
    setMenuOpen({ open: false, anchorEl: null });
  };
  const handleOpenOptions = (selectedAction: 'container-report' | 'summarize-files' | 'convert-files') => {
    handleCloseMenu();
    setAction(selectedAction);
    setFormat(actionsFormat[selectedAction][0] as 'html' | 'markdown' | 'text' | 'json' ?? 'html');
    setOptionsOpen(true);
  };
  const handleCloseOptions = () => {
    setOptionsOpen(false);
  };
  const handleOpenAskAI = () => setDisplayAskAI(true);
  const handleCloseAskAI = () => setDisplayAskAI(false);
  const [commitMutationUpdateContent] = useApiMutation<StixCoreObjectMappableContentFieldPatchMutation>(stixCoreObjectMappableContentFieldPatchMutation);
  const [commitMutationCreateFile] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(stixCoreObjectContentFilesUploadStixCoreObjectMutation);
  const [commitMutationContainerReport] = useApiMutation<StixCoreObjectAskAIContainerReportMutation>(stixCoreObjectAskAIContainerReportMutation);
  const [commitMutationSummarizeFiles] = useApiMutation<StixCoreObjectAskAISummarizeFilesMutation>(stixCoreObjectAskAISummarizeFilesMutation);
  const [commitMutationConvertFilesToStix] = useApiMutation<StixCoreObjectAskAIConvertFilesToStixMutation>(stixCoreObjectAskAIConvertFilesToStixMutation);
  const handleAskAiContent = () => {
    handleCloseOptions();
    setDisableResponse(true);
    const id = uuid();
    setBusId(id);
    handleOpenAskAI();
    switch (action) {
      case 'container-report':
        commitMutationContainerReport({
          variables: {
            id,
            containerId: instanceId,
            paragraphs,
            tone,
            format,
          },
          onCompleted: (response: StixCoreObjectAskAIContainerReportMutation$data) => {
            setContent(response?.aiContainerGenerateReport ?? '');
            setDisableResponse(false);
          },
          onError: (error: Error) => {
            setContent(t_i18n(`An unknown error occurred, please ask your platform administrator: ${error.toString()}`));
            setDisableResponse(false);
          },
        });
        break;
      case 'summarize-files':
        commitMutationSummarizeFiles({
          variables: {
            id,
            elementId: instanceId,
            paragraphs,
            tone,
            format,
            fileIds: files.map((n) => n.value),
          },
          onCompleted: (response: StixCoreObjectAskAISummarizeFilesMutation$data) => {
            setContent(response?.aiSummarizeFiles ?? '');
            setDisableResponse(false);
          },
          onError: (error: Error) => {
            setContent(t_i18n(`An unknown error occurred, please ask your platform administrator: ${error.toString()}`));
            setDisableResponse(false);
          },
        });
        break;
      case 'convert-files':
        setDestination('file');
        commitMutationConvertFilesToStix({
          variables: {
            id,
            elementId: instanceId,
            fileIds: files.map((n) => n.value),
          },
          onCompleted: (response: StixCoreObjectAskAIConvertFilesToStixMutation$data) => {
            setContent(response?.aiConvertFilesToStix ?? '');
            setDisableResponse(false);
          },
          onError: (error: Error) => {
            setContent(t_i18n(`An unknown error occurred, please ask your platform administrator: ${error.toString()}`));
            setDisableResponse(false);
          },
        });
        break;
      default:
      // do nothing
    }
  };
  const handleAskAi = () => {
    // check paragraphs value is correct
    if (action === 'container-report' || action === 'summarize-files') {
      if (Number.isNaN(paragraphs)) {
        MESSAGING$.notifyError('Number of paragraphs should be a number');
      } else if (paragraphs <= 0) {
        MESSAGING$.notifyError('Number of paragraphs should be greather than 0');
      } else {
        handleAskAiContent();
      }
    } else {
      handleAskAiContent();
    }
  };
  const handleCancelDestination = () => {
    setAcceptedResult(null);
    setDisplayAskAI(true);
  };
  const submitAcceptedResult = () => {
    setIsSubmitting(true);
    if (destination === 'content') {
      const inputValues = [{ key: 'content', value: [acceptedResult] }];
      commitMutationUpdateContent({
        variables: {
          id: instanceId,
          input: inputValues,
        },
        onCompleted: () => {
          setAcceptedResult(null);
          setIsSubmitting(false);
          navigate({
            pathname: `${resolveLink(instanceType)}/${instanceId}/content`,
            search: `${createSearchParams({ contentSelected: 'true' })}`,
          });
        },
      });
    } else if (destination === 'file') {
      let fileName = newFileName ?? instanceName;
      if (format === 'text') {
        fileName += '.txt';
      } else if (format === 'html') {
        fileName += '.html';
      } else if (format === 'markdown') {
        fileName += '.md';
      } else if (format === 'json') {
        fileName += '.json';
      }
      const blob = new Blob([acceptedResult ?? ''], {
        type,
      });
      const file = new File([blob], fileName, {
        type,
      });
      const fileMarkings = instanceMarkings ?? [];
      commitMutationCreateFile({
        variables: {
          id: instanceId,
          file,
          fileMarkings,
          noTriggerImport: false,
        },
        onCompleted: (response: StixCoreObjectContentFilesUploadStixCoreObjectMutation$data) => {
          setAcceptedResult(null);
          setIsSubmitting(false);
          navigate({
            pathname: `${resolveLink(instanceType)}/${instanceId}/${type === 'container' && format !== 'json' ? 'content' : 'files'}`,
            search: `${createSearchParams({ forceFile: 'true', currentFileId: response?.stixCoreObjectEdit?.importPush?.id ?? '' })}`,
          });
        },
      });
    }
  };
  return (
    <>
      <EETooltip forAi={true} title={t_i18n('Ask AI')}>
        <ToggleButton
          onClick={(event) => ((isEnterpriseEdition && enabled && configured) ? handleOpenMenu(event) : null)}
          value="ask-ai"
          size="small"
          style={{ marginRight: 3 }}
        >
          <AutoAwesomeOutlined fontSize="small" color="secondary" />
        </ToggleButton>
      </EETooltip>
      <Menu
        id="menu-appbar"
        anchorEl={menuOpen.anchorEl}
        open={menuOpen.open}
        onClose={handleCloseMenu}
      >
        {type === 'container' && (
          <MenuItem onClick={() => handleOpenOptions('container-report')}>
            {t_i18n('Generate report document')}
          </MenuItem>
        )}
        <MenuItem onClick={() => handleOpenOptions('summarize-files')}>
          {t_i18n('Summarize associated files')}
        </MenuItem>
        {isKnowledgeUploader && (
          <MenuItem onClick={() => handleOpenOptions('convert-files')}>
            {t_i18n('Convert associated files to STIX 2.1')}
          </MenuItem>
        )}
      </Menu>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={optionsOpen}
        onClose={handleCloseOptions}
        fullWidth={true}
        maxWidth="xs"
      >
        <DialogTitle>{t_i18n('Select options')}</DialogTitle>
        <DialogContent>
          <Alert severity="info">
            {action && t_i18n(actionsExplanation[action])}
          </Alert>
          <FormControl style={fieldSpacingContainerStyle}>
            <InputLabel id="format">{t_i18n('Format')}</InputLabel>
            <Select
              labelId="format"
              value={format}
              onChange={(event) => setFormat(event.target.value as unknown as 'html' | 'markdown' | 'text' | 'json')}
              fullWidth={true}
            >
              {action && actionsFormat[action].includes('html') && <MenuItem value="html">{t_i18n('HTML')}</MenuItem>}
              {action && actionsFormat[action].includes('markdown') && <MenuItem value="markdown">{t_i18n('Markdown')}</MenuItem>}
              {action && actionsFormat[action].includes('text') && <MenuItem value="text">{t_i18n('Plain text')}</MenuItem>}
              {action && actionsFormat[action].includes('json') && <MenuItem value="json">{t_i18n('JSON')}</MenuItem>}
            </Select>
          </FormControl>
          {action && actionsOptions[action].includes('tone') && (
            <FormControl style={fieldSpacingContainerStyle}>
              <InputLabel id="tone">{t_i18n('Tone')}</InputLabel>
              <Select
                labelId="tone"
                value={tone}
                onChange={(event) => setTone(event.target.value as unknown as 'tactical' | 'operational' | 'strategic')}
                fullWidth={true}
              >
                <MenuItem value="tactical">{t_i18n('Tactical')}</MenuItem>
                <MenuItem value="operational">{t_i18n('Operational')}</MenuItem>
                <MenuItem value="strategic">{t_i18n('Strategic')}</MenuItem>
              </Select>
            </FormControl>
          )}
          {action && actionsOptions[action].includes('paragraphs') && (
            <TextField
              label={t_i18n('Number of paragraphs')}
              fullWidth={true}
              type="number"
              value={paragraphs}
              onChange={(event) => setParagraphs(parseInt(event.target.value, 10))}
              style={fieldSpacingContainerStyle}
            />
          )}
          {action && actionsOptions[action].includes('files') && (
            <FilesNativeField
              stixCoreObjectId={instanceId}
              name="fileIds"
              label={t_i18n('Files')}
              currentValue={files}
              onChange={(value) => value && setFiles(value)}
              containerStyle={fieldSpacingContainerStyle}
              helperText={t_i18n('By default, all files will be used to generate the response.')}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseOptions}
            disabled={isSubmitting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleAskAi}
            disabled={isSubmitting}
            color="secondary"
          >
            {t_i18n('Generate')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={acceptedResult !== null}
        onClose={() => setAcceptedResult(null)}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t_i18n('Select destination')}</DialogTitle>
        <DialogContent>
          <List>
            {isContainerWithContent(instanceType) && format !== 'json' && (
              <ListItem dense={true} divider={true}>
                <ListItemText
                  primary={t_i18n('Main content')}
                  secondary={t_i18n('Put in the embedded content of the entity')}
                />
                <ListItemSecondaryAction>
                  <Radio
                    checked={destination === 'content'}
                    onChange={() => setDestination('content')}
                    value="content"
                    name="destination"
                    inputProps={{ 'aria-label': 'destination' }}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            )}
            {isKnowledgeUploader && (
              <ListItem dense={true} divider={true}>
                <ListItemText
                  primary={t_i18n('New file')}
                  secondary={t_i18n('Create a new file with the content')}
                />
                <ListItemSecondaryAction>
                  <Radio
                    checked={destination === 'file'}
                    onChange={() => setDestination('file')}
                    value="file"
                    name="destination"
                    inputProps={{ 'aria-label': 'destination' }}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            )}
          </List>
          {destination === 'file' && (
            <TextField
              label={t_i18n('File name')}
              fullWidth={true}
              value={newFileName ?? instanceName}
              onChange={(event) => setNewFileName(event.target.value as unknown as string)}
              style={fieldSpacingContainerStyle}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelDestination} disabled={isSubmitting}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitAcceptedResult}
            disabled={isSubmitting}
            color="secondary"
          >
            {t_i18n('Submit')}
          </Button>
        </DialogActions>
      </Dialog>
      {busId && (
        <ResponseDialog
          id={busId}
          isDisabled={disableResponse}
          isOpen={displayAskAI}
          handleClose={handleCloseAskAI}
          content={content}
          setContent={setContent}
          handleAccept={(value) => {
            setAcceptedResult(value);
            handleCloseAskAI();
          }}
          handleFollowUp={handleCloseAskAI}
          followUpActions={[{ key: 'retry', label: t_i18n('Retry') }]}
          format={format}
        />
      )}
    </>
  );
};

export default StixCoreObjectAskAI;
