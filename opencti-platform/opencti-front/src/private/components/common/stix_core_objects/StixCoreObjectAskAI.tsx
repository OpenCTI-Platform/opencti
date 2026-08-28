import React, { FunctionComponent, useState } from 'react';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import { DialogTitle } from '@mui/material';
import Dialog from '@common/dialog/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Radio from '@mui/material/Radio';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import TextField from '@mui/material/TextField';
import { createSearchParams, useNavigate } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import { StixCoreObjectMappableContentFieldPatchMutation } from '@components/common/stix_core_objects/__generated__/StixCoreObjectMappableContentFieldPatchMutation.graphql';
import {
  StixCoreObjectAskAIContainerReportMutation,
  StixCoreObjectAskAIContainerReportMutation$data,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectAskAIContainerReportMutation.graphql';
import type {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
  StixCoreObjectContentFilesUploadStixCoreObjectMutation$data,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from './StixCoreObjectContentFiles';
import { stixCoreObjectMappableContentFieldPatchMutation } from './StixCoreObjectMappableContent';
import FilesNativeField from '../form/FilesNativeField';
import { useFormatter } from '../../../../components/i18n';
import ResponseDialog from '../../../../utils/ai/ResponseDialog';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { resolveLink } from '../../../../utils/Entity';
import useGranted, { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { aiLanguage } from '../../../../components/AppIntlProvider';
import { getDefaultAiLanguage } from '../../../../utils/ai/Common';

// region types
interface StixCoreObjectAskAiProps {
  instanceId: string;
  instanceName: string;
  instanceType: string;
  instanceMarkings?: string[];
  type: 'container' | 'threat' | 'victim' | 'unsupported';
  optionsOpen: boolean;
  handleCloseOptions: () => void;
}

const isContainerWithContent = (type: string) => ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].includes(type);

const stixCoreObjectAskAIContainerReportMutation = graphql`
  mutation StixCoreObjectAskAIContainerReportMutation($id: ID!, $containerId: String!, $paragraphs: Int, $tone: Tone, $format: Format, $language: String) {
    aiContainerGenerateReport(id: $id, containerId: $containerId, paragraphs: $paragraphs, tone: $tone, format: $format, language: $language)
  }
`;

const actionsOptions = {
  'container-report': ['format', 'paragraphs', 'tone', 'language'],
  'summarize-files': ['format', 'paragraphs', 'tone', 'files', 'language'],
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

const StixCoreObjectAskAI: FunctionComponent<StixCoreObjectAskAiProps> = ({
  instanceId,
  instanceType,
  instanceName,
  type,
  instanceMarkings,
  optionsOpen,
  handleCloseOptions,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isKnowledgeUploader = useGranted([KNOWLEDGE_KNUPLOAD]);
  const defaultLanguageName = getDefaultAiLanguage();

  const [language, setLanguage] = useState(defaultLanguageName);
  const [content, setContent] = useState('');
  const [acceptedResult, setAcceptedResult] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [format, setFormat] = useState<'html' | 'markdown' | 'text' | 'json'>('html');
  const [destination, setDestination] = useState<'content' | 'file'>('content');
  const [newFileName, setNewFileName] = useState<string | null>(null);
  const [tone, setTone] = useState<'tactical' | 'operational' | 'strategic'>('tactical');
  const [paragraphs, setParagraphs] = useState(10);
  const [files, setFiles] = useState<{ label: string; value: string }[]>([]);
  const [disableResponse, setDisableResponse] = useState(false);
  const [busId, setBusId] = useState<string | null>(null);
  const [displayAskAI, setDisplayAskAI] = useState(false);

  const action = 'container-report' as 'container-report' | 'summarize-files' | 'convert-files';
  const handleOpenAskAI = () => setDisplayAskAI(true);
  const handleCloseAskAI = () => {
    setContent('');
    setDisplayAskAI(false);
  };

  const [commitMutationUpdateContent] = useApiMutation<StixCoreObjectMappableContentFieldPatchMutation>(stixCoreObjectMappableContentFieldPatchMutation);
  const [commitMutationCreateFile] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(stixCoreObjectContentFilesUploadStixCoreObjectMutation);
  const [commitMutationContainerReport] = useApiMutation<StixCoreObjectAskAIContainerReportMutation>(stixCoreObjectAskAIContainerReportMutation);

  const handleAskAiContent = () => {
    handleCloseOptions();
    setDisableResponse(true);
    const id = uuid();
    setBusId(id);
    handleOpenAskAI();
    commitMutationContainerReport({
      variables: {
        id,
        containerId: instanceId,
        paragraphs,
        tone,
        format,
        language,
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
  };

  const handleAskAi = () => {
    // check paragraphs value is correct
    if (action === 'container-report' || action === 'summarize-files') {
      if (Number.isNaN(paragraphs)) {
        MESSAGING$.notifyError(t_i18n('Number of paragraphs should be a number'));
      } else if (paragraphs <= 0) {
        MESSAGING$.notifyError(t_i18n('Number of paragraphs should be greater than 0'));
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
      <Dialog
        open={optionsOpen}
        onClose={handleCloseOptions}
        title={t_i18n('Select options')}
      >
        <Alert severity="info">
          {action && t_i18n(actionsExplanation[action])}
        </Alert>
        <Select
          value={format}
          onValueChange={(value) => setFormat(value as 'html' | 'markdown' | 'text' | 'json')}
        >
          <SelectLabel>{t_i18n('Format')}</SelectLabel>
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Format')}>
            {action && actionsFormat[action].includes('html') && <SelectItem value="html">{t_i18n('HTML')}</SelectItem>}
            {action && actionsFormat[action].includes('markdown') && <SelectItem value="markdown">{t_i18n('Markdown')}</SelectItem>}
            {action && actionsFormat[action].includes('text') && <SelectItem value="text">{t_i18n('Plain text')}</SelectItem>}
            {action && actionsFormat[action].includes('json') && <SelectItem value="json">{t_i18n('JSON')}</SelectItem>}
          </SelectContent>
        </Select>
        {action && actionsOptions[action].includes('tone') && (
          <Select
            value={tone}
            onValueChange={(value) => setTone(value as 'tactical' | 'operational' | 'strategic')}
          >
            <SelectLabel>{t_i18n('Tone')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Tone')}>
              <SelectItem value="tactical">{t_i18n('Tactical')}</SelectItem>
              <SelectItem value="operational">{t_i18n('Operational')}</SelectItem>
              <SelectItem value="strategic">{t_i18n('Strategic')}</SelectItem>
            </SelectContent>
          </Select>
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
        {action && actionsOptions[action].includes('language') && (
          <Select
            value={language}
            onValueChange={setLanguage}
          >
            <SelectLabel>{t_i18n('Language')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Language')}>
              {aiLanguage.map((lang) => (
                <SelectItem key={lang.value} value={lang.name}>{t_i18n(lang.name)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseOptions}
            disabled={isSubmitting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleAskAi}
            disabled={isSubmitting}
          >
            {t_i18n('Generate')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={acceptedResult !== null}
        onClose={() => setAcceptedResult(null)}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t_i18n('Select destination')}</DialogTitle>
        <DialogContent>
          <List>
            {isContainerWithContent(instanceType) && format !== 'json' && (
              <ListItem
                dense={true}
                divider={true}
                secondaryAction={(
                  <Radio
                    checked={destination === 'content'}
                    onChange={() => setDestination('content')}
                    value="content"
                    name="destination"
                    inputProps={{ 'aria-label': 'destination' }}
                  />
                )}
              >
                <ListItemText
                  primary={t_i18n('Main content')}
                  secondary={t_i18n('Put in the embedded content of the entity')}
                />
              </ListItem>
            )}
            {isKnowledgeUploader && (
              <ListItem
                dense={true}
                divider={true}
                secondaryAction={(
                  <Radio
                    checked={destination === 'file'}
                    onChange={() => setDestination('file')}
                    value="file"
                    name="destination"
                    inputProps={{ 'aria-label': 'destination' }}
                  />
                )}
              >
                <ListItemText
                  primary={t_i18n('New file')}
                  secondary={t_i18n('Create a new file with the content')}
                />
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
          <Button variant="secondary" onClick={handleCancelDestination} disabled={isSubmitting}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitAcceptedResult}
            disabled={isSubmitting}
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
