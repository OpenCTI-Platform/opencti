import React, { FunctionComponent, useState } from 'react';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { v4 as uuid } from 'uuid';
import { graphql, useMutation } from 'react-relay';
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
import { createSearchParams, useNavigate } from 'react-router-dom-v5-compat';
import { stixDomainObjectContentFilesUploadStixDomainObjectMutation } from '../stix_domain_objects/StixDomainObjectContentFiles';
import { stixDomainObjectContentFieldPatchMutation } from '../stix_domain_objects/StixDomainObjectContent';
import FilesNativeField from '../form/FilesNativeField';
import type {
  StixDomainObjectContentFilesUploadStixDomainObjectMutation,
  StixDomainObjectContentFilesUploadStixDomainObjectMutation$data,
} from '../stix_domain_objects/__generated__/StixDomainObjectContentFilesUploadStixDomainObjectMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import ResponseDialog from '../../../../utils/ai/ResponseDialog';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAI from '../../../../utils/hooks/useAI';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { resolveLink } from '../../../../utils/Entity';

// region types
interface StixCoreObjectAskAiProps {
  instanceId: string;
  instanceName: string;
  instanceType: string;
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

const StixCoreObjectAskAI: FunctionComponent<StixCoreObjectAskAiProps> = ({ instanceId, instanceType, instanceName, type }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured } = useAI();
  const [action, setAction] = useState<'container-report' | 'summarize-files' | 'convert-files' | null>(null);
  const [acceptedResult, setAcceptedResult] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [destination, setDestination] = useState<'content' | 'file'>('content');
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [tone, setTone] = useState<'technical' | 'tactical' | 'strategical'>('technical');
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
  const [commitMutationUpdateContent] = useMutation(stixDomainObjectContentFieldPatchMutation);
  const [commitMutationCreateFile] = useMutation<StixDomainObjectContentFilesUploadStixDomainObjectMutation>(stixDomainObjectContentFilesUploadStixDomainObjectMutation);
  const [commitMutationContainerReport] = useMutation(stixCoreObjectAskAIContainerReportMutation);
  const [commitMutationSummarizeFiles] = useMutation(stixCoreObjectAskAISummarizeFilesMutation);
  const [commitMutationConvertFilesToStix] = useMutation(stixCoreObjectAskAIConvertFilesToStixMutation);
  const handleAskAi = () => {
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
          onCompleted: () => {
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
          onCompleted: () => {
            setDisableResponse(false);
          },
        });
        break;
      case 'convert-files':
        commitMutationConvertFilesToStix({
          variables: {
            id,
            elementId: instanceId,
            fileIds: files.map((n) => n.value),
          },
          onCompleted: () => {
            setDisableResponse(false);
          },
        });
        break;
      default:
        // do nothing
    }
  };
  const handleCancelDestination = () => {
    setAcceptedResult(null);
    setDisplayAskAI(true);
  };
  const submitAcceptedResult = () => {
    setIsSubmitting(true);
    if (destination === 'content') {
      const inputValues = [{ key: 'content', value: acceptedResult }];
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
    }
    let name = instanceName;
    if (format === 'text') {
      name += '.txt';
    } else if (format === 'html') {
      name += '.html';
    } else if (format === 'markdown') {
      name += '.md';
    } else if (format === 'json') {
      name += '.json';
    }
    const blob = new Blob([acceptedResult ?? ''], {
      type,
    });
    const file = new File([blob], name, {
      type,
    });
    commitMutationCreateFile({
      variables: {
        id: instanceId,
        file,
        noTriggerImport: false,
      },
      onCompleted: (response: StixDomainObjectContentFilesUploadStixDomainObjectMutation$data) => {
        setAcceptedResult(null);
        setIsSubmitting(false);
        navigate({
          pathname: `${resolveLink(instanceType)}/${instanceId}/${type === 'container' && format !== 'json' ? 'content' : 'files'}`,
          search: `${createSearchParams({ currentFileId: response?.stixDomainObjectEdit?.importPush?.id ?? '' })}`,
        });
      },
    });
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
        <MenuItem onClick={() => handleOpenOptions('convert-files')}>
          {t_i18n('Convert associated files to STIX')}
        </MenuItem>
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
          <FormControl style={{ width: '100%' }}>
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
                onChange={(event) => setTone(event.target.value as unknown as 'technical' | 'tactical' | 'strategical')}
                fullWidth={true}
              >
                <MenuItem value="technical">{t_i18n('Technical')}</MenuItem>
                <MenuItem value="tactical">{t_i18n('Tactical')}</MenuItem>
                <MenuItem value="strategical">{t_i18n('Strategical')}</MenuItem>
              </Select>
            </FormControl>
          )}
          {action && actionsOptions[action].includes('paragraphs') && (
            <TextField
              label={t_i18n('Number of paragraphs')}
              fullWidth={true}
              type="number"
              value={paragraphs}
              onChange={(event) => setParagraphs(event.target.value as unknown as number)}
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
          </List>
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
