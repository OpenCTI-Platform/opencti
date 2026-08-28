import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { RefreshOutlined } from '@mui/icons-material';
import Alert from '@mui/material/Alert';

import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import DialogActions from '@mui/material/DialogActions';
import IconButton from '@mui/material/IconButton';
import {
  Combobox,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@filigran/design-system';
import TextField from '@mui/material/TextField';
import { FunctionComponent, useEffect, useMemo, useRef, useState } from 'react';
import ReactMde from 'react-mde';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';

import { RichTextEditor } from '@filigran/rich-text-editor';
import { useFormatter } from '../../components/i18n';
import MarkdownDisplay from '../../components/markdownDisplay/MarkdownDisplay';
import { isNotEmptyField } from '../utils';
import { ResponseDialogAskAISubscription, ResponseDialogAskAISubscription$data } from './__generated__/ResponseDialogAskAISubscription.graphql';
import type { AgentAction } from '../../private/components/common/form/TextFieldAskAI';
// Circular dependency is intentional: TextFieldAskAI opens ResponseDialog,
// and in legacy mode ResponseDialog embeds TextFieldAskAI for follow-up actions.
import TextFieldAskAI from '../../private/components/common/form/TextFieldAskAI';
import useAI from '../hooks/useAI';
import { type AgentOption, fetchAgentsForIntent } from './agentApi';
import useAgentStream from './useAgentStream';

// region types
interface ResponseDialogProps {
  id: string;
  isOpen: boolean;
  isDisabled: boolean;
  handleClose: () => void;
  handleAccept: (content: string) => void;
  handleFollowUp: () => void;
  content: string;
  setContent: (content: string) => void;
  format: 'text' | 'html' | 'markdown' | 'json';
  isAcceptable?: boolean;
  followUpActions: {
    key: string;
    label: string;
  }[];
  agentMode?: {
    intent: string;
    action: AgentAction;
    inputContent: string;
    format: string;
  } | null;
}

const subscription = graphql`
    subscription ResponseDialogAskAISubscription($id: ID!) {
        aiBus(id: $id) {
          content
        }
    }
`;

const buildPrompt = (
  action: AgentAction,
  inputContent: string,
  format: string,
  tone?: string,
): string => {
  switch (action) {
    case 'spelling':
      return `Fix the spelling and grammar of the following content. Keep the same ${format} format. Return only the corrected result, no explanation.\n\n${inputContent}`;
    case 'shorter':
      return `Make the following content shorter. Keep the same ${format} format. Return only the result, no explanation.\n\n${inputContent}`;
    case 'longer':
      return `Make the following content longer and more detailed. Keep the same ${format} format. Return only the result, no explanation.\n\n${inputContent}`;
    case 'tone':
      return `Change the tone of the following content to be more ${tone ?? 'tactical'}. Keep the same ${format} format. Return only the result, no explanation.\n\n${inputContent}`;
    case 'summarize':
      return `Summarize the following content. Keep the same ${format} format. Return only the summary, no explanation.\n\n${inputContent}`;
    case 'explain':
      return `Explain the following content in simple terms. Return only the explanation.\n\n${inputContent}`;
    default:
      return inputContent;
  }
};

// ── Component ───────────────────────────────────────────────────────────

const ResponseDialog: FunctionComponent<ResponseDialogProps> = ({
  id,
  isOpen,
  isDisabled,
  handleClose,
  handleAccept,
  format,
  isAcceptable = true,
  content,
  setContent,
  agentMode = null,
}) => {
  const textFieldRef = useRef<HTMLTextAreaElement>(null);
  const markdownFieldRef = useRef<HTMLTextAreaElement>(null);
  const { t_i18n } = useFormatter();
  const [markdownSelectedTab, setMarkdownSelectedTab] = useState<'write' | 'preview' | undefined>('write');
  const { fullyActive } = useAI();
  const isLegacyMode = !agentMode;

  // Agent mode state (XTM One path)
  const [agentOptions, setAgentOptions] = useState<AgentOption[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<AgentOption | null>(null);
  const [loadingAgents, setLoadingAgents] = useState(false);
  // Agent streaming hook
  const { content: streamContent, loading: agentLoading, error: agentError, execute: executeStream, abort: abortStream } = useAgentStream();

  // Sync streamed content to parent's setContent
  useEffect(() => {
    if (streamContent) setContent(streamContent);
  }, [streamContent, setContent]);

  const [agentExecuted, setAgentExecuted] = useState(false);

  // Tone selector (for change tone action in agent mode)
  const [tone, setTone] = useState<string>('tactical');

  // Load agents when dialog opens in agent mode
  useEffect(() => {
    if (isOpen && agentMode) {
      setAgentExecuted(false);
      abortStream();
      setLoadingAgents(true);
      setSelectedAgent(null);
      setAgentOptions([]);
      fetchAgentsForIntent(agentMode.intent).then((agents) => {
        setAgentOptions(agents);
        setLoadingAgents(false);
        if (agents.length > 0) {
          setSelectedAgent(agents[0]);
        }
      });
    }
    if (!isOpen) {
      setAgentExecuted(false);
      abortStream();
    }
  }, [isOpen, agentMode?.intent, agentMode?.action]);

  // Auto-execute when agent is selected
  useEffect(() => {
    if (isOpen && agentMode && selectedAgent && !agentExecuted && !agentLoading) {
      executeAgentCall();
    }
  }, [selectedAgent, isOpen, agentMode, agentExecuted, agentLoading]);

  // Re-execute when tone changes
  const toneRef = useRef(tone);
  useEffect(() => {
    if (toneRef.current !== tone && isOpen && agentMode && selectedAgent && agentExecuted) {
      toneRef.current = tone;
      executeAgentCall();
    }
  }, [tone]);

  const executeAgentCall = () => {
    if (!selectedAgent || !agentMode) return;
    setAgentExecuted(true);
    const prompt = buildPrompt(agentMode.action, agentMode.inputContent, agentMode.format, tone);
    executeStream(selectedAgent.slug, prompt);
  };

  const handleRefresh = () => {
    if (!selectedAgent || !agentMode) return;
    setContent('');
    setAgentExecuted(false);
  };

  const handleAgentChange = (newValue: AgentOption | null) => {
    if (!newValue) return;
    setSelectedAgent(newValue);
    if (agentMode) {
      setAgentExecuted(false);
      setContent('');
    }
  };

  // GraphQL subscription (used in both modes, fires when aiBus emits)
  const handleResponse = (response: ResponseDialogAskAISubscription$data | null | undefined) => {
    const newContent = response ? (response as ResponseDialogAskAISubscription$data).aiBus?.content : null;
    if (format === 'text' || format === 'json') {
      if (isNotEmptyField(textFieldRef?.current?.scrollTop)) {
        textFieldRef.current.scrollTop = textFieldRef.current.scrollHeight;
      }
    } else if (format === 'markdown') {
      if (isNotEmptyField(markdownFieldRef?.current?.scrollTop)) {
        markdownFieldRef.current.scrollTop = markdownFieldRef.current.scrollHeight;
      }
    } else if (format === 'html') {
      const elementEditor = document.querySelector('.tiptap-editor-content.ProseMirror');
      elementEditor?.lastElementChild?.scrollIntoView();
    }
    return setContent(newContent ?? '');
  };
  const subConfig = useMemo<
    GraphQLSubscriptionConfig<ResponseDialogAskAISubscription>>(
    () => ({
      subscription,
      variables: { id },
      onNext: handleResponse,
    }),
    [id],
  );
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useSubscription(subConfig);
  const height = 400;

  const effectiveDisabled = isDisabled || agentLoading;
  const noAgents = agentMode && !loadingAgents && agentOptions.length === 0;

  // ── Title ─────────────────────────────────────────────────────────────

  const dialogTitle = agentMode ? (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', gap: 2 }}>
      <span>{t_i18n('Ask AI')}</span>
      <Combobox<AgentOption>
        labelPosition="none"
        options={agentOptions}
        getOptionLabel={(option) => option?.name ?? ''}
        value={selectedAgent ?? null}
        onValueChange={(next) => handleAgentChange(next as AgentOption | null)}
        // Replaces the CircularProgress hand-mounted in the input's endAdornment.
        loading={loadingAgents}
        disabled={noAgents as boolean}
        isOptionEqualToValue={(option, value) => option.id === value.id}
        // `clearIcon={null}` was MUI's other way of removing the clear button.
        clearable={false}
      >
        <ComboboxField>
          <ComboboxInput
            aria-label={t_i18n('Select agent')}
            placeholder={noAgents ? t_i18n('No agent available') : t_i18n('Select agent')}
          />
          <ComboboxControls>
            <ComboboxTrigger />
          </ComboboxControls>
        </ComboboxField>
        <ComboboxContent
          emptyMessage={t_i18n('Ask your administrator to configure XTM One')}
          listAriaLabel={t_i18n('Select agent')}
        />
      </Combobox>
    </Box>
  ) : t_i18n('Ask AI');

  const renderRefreshButton = () => {
    if (!agentMode) return null;
    return (
      <IconButton
        size="small"
        aria-label={t_i18n('Refresh')}
        onClick={handleRefresh}
        disabled={agentLoading || !selectedAgent}
        sx={{ position: 'absolute', top: 2, right: 2, zIndex: 1 }}
      >
        <RefreshOutlined fontSize="small" />
      </IconButton>
    );
  };

  // ── Content editors ───────────────────────────────────────────────────

  const renderContentEditors = () => (
    <>
      {(format === 'text' || format === 'json') && (
        <TextField
          inputRef={textFieldRef}
          disabled={effectiveDisabled}
          rows={Math.round(height / 23)}
          value={content}
          multiline={true}
          onChange={(event) => setContent(event.target.value)}
          fullWidth={true}
          slotProps={isLegacyMode && fullyActive ? {
            input: {
              endAdornment: (
                <TextFieldAskAI
                  currentValue={content ?? ''}
                  setFieldValue={(val) => setContent(val)}
                  format="text"
                  variant="text"
                  disabled={isDisabled}
                />
              ),
            },
          } : undefined}
        />
      )}
      {format === 'html' && (
        <RichTextEditor
          id="response-dialog-editor"
          data={content}
          onChange={(_, adapter) => {
            setContent(adapter.getData());
          }}
          disabled={effectiveDisabled}
        />
      )}
      {format === 'markdown' && (
        <ReactMde
          childProps={{
            textArea: {
              ref: markdownFieldRef,
            },
          }}
          readOnly={effectiveDisabled}
          value={content}
          minEditorHeight={height - 80}
          maxEditorHeight={height - 80}
          onChange={setContent}
          selectedTab={markdownSelectedTab}
          onTabChange={setMarkdownSelectedTab}
          generateMarkdownPreview={(markdown) => Promise.resolve(
            <MarkdownDisplay
              content={markdown}
              remarkGfmPlugin={true}
              commonmark={true}
            />,
          )}
          l18n={{
            write: t_i18n('Write'),
            preview: t_i18n('Preview'),
            uploadingImage: t_i18n('Uploading image'),
            pasteDropSelect: t_i18n('Paste'),
          }}
        />
      )}
      {/* Legacy embedded TextFieldAskAI for html/markdown formats */}
      {isLegacyMode && (format === 'markdown' || format === 'html') && (
        <TextFieldAskAI
          currentValue={content ?? ''}
          setFieldValue={(val) => setContent(val)}
          format={format}
          variant={format}
          disabled={isDisabled}
          style={format === 'html' ? { position: 'absolute', top: 2, right: 45 } : undefined}
        />
      )}
    </>
  );

  return (
    <>
      <Dialog
        open={isOpen}
        onClose={() => {
          setContent('');
          handleClose();
        }}
        title={dialogTitle}
      >
        {/* Agent mode: tone selector */}
        {agentMode?.action === 'tone' && (
          <Box sx={{ mb: 2 }}>
            <Select value={tone} onValueChange={setTone}>
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
          </Box>
        )}

        <div style={{ width: '100%', minHeight: height, height, position: 'relative' }}>
          {agentMode && (
            <>
              {renderRefreshButton()}

              {((agentLoading && !content) || loadingAgents) && (
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                  <CircularProgress size={40} />
                </Box>
              )}

              {noAgents && !agentLoading && (
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                  <Alert severity="info" variant="outlined">
                    {t_i18n('No agent available for this action. Ask your administrator to configure XTM One.')}
                  </Alert>
                </Box>
              )}

              {agentError && !agentLoading && (
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                  <Alert severity="error" variant="outlined">
                    {agentError}
                  </Alert>
                </Box>
              )}

              {(!agentLoading || content) && !loadingAgents && !noAgents && !agentError && renderContentEditors()}
            </>
          )}

          {/* Legacy mode: always show content editors */}
          {isLegacyMode && renderContentEditors()}
        </div>
        <div className="clearfix" />

        {/* Legacy mode: beta warning */}
        {isLegacyMode && (
          <Alert severity="warning" variant="outlined" style={format === 'html' ? { marginTop: 30 } : {}}>
            {t_i18n('Generative AI is a beta feature as we are currently fine-tuning our models. Consider checking important information.')}
          </Alert>
        )}

        <DialogActions>
          <Button variant="secondary" onClick={handleClose}>
            {t_i18n('Close')}
          </Button>
          {isAcceptable && (
            <Button
              disabled={effectiveDisabled || !!agentError}
              onClick={() => handleAccept(content)}
            >
              {t_i18n('Accept')}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ResponseDialog;
