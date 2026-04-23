import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { RefreshOutlined } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import Autocomplete from '@mui/material/Autocomplete';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import DialogActions from '@mui/material/DialogActions';
import FormControl from '@mui/material/FormControl';
import IconButton from '@mui/material/IconButton';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import { FunctionComponent, useEffect, useMemo, useRef, useState } from 'react';
import ReactMde from 'react-mde';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';

import RichTextEditor from '../../components/RichTextEditor';
import CKEditor from '../../components/CKEditor';
import { useFormatter } from '../../components/i18n';
import MarkdownDisplay from '../../components/MarkdownDisplay';
import { isNotEmptyField } from '../utils';
import { ResponseDialogAskAISubscription, ResponseDialogAskAISubscription$data } from './__generated__/ResponseDialogAskAISubscription.graphql';
import type { AgentAction } from '../../private/components/common/form/TextFieldAskAI';
// Circular dependency is intentional: TextFieldAskAI opens ResponseDialog,
// and in legacy mode ResponseDialog embeds TextFieldAskAI for follow-up actions.
import TextFieldAskAI from '../../private/components/common/form/TextFieldAskAI';
import useAI from '../hooks/useAI';
import useHelper from '../hooks/useHelper';

// region types

interface AgentOption {
  id: string;
  name: string;
  slug: string;
  description?: string;
}

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

// ── XTM One agent helpers ───────────────────────────────────────────────

const fetchAgentsForIntent = async (intent: string): Promise<AgentOption[]> => {
  try {
    const response = await fetch(`/chatbot/agents?intent=${encodeURIComponent(intent)}`);
    if (!response.ok) return [];
    return await response.json();
  } catch {
    return [];
  }
};

interface AgentResponse {
  content: string;
  status: 'success' | 'error';
  error?: string;
  code?: number;
}

const callAgent = async (agentSlug: string, content: string): Promise<AgentResponse> => {
  const response = await fetch('/chatbot/agent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_slug: agentSlug, content }),
  });
  if (!response.ok) {
    return { content: '', status: 'error', error: `Agent call failed: ${response.statusText}`, code: response.status };
  }
  const data = await response.json();
  return {
    content: data.content ?? '',
    status: data.status ?? 'success',
    error: data.error,
    code: data.code,
  };
};

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
  const { isTiptapEditorEnable } = useHelper();
  const tiptapEnabled = isTiptapEditorEnable();
  const isLegacyMode = !agentMode;

  // Agent mode state (XTM One path)
  const [agentOptions, setAgentOptions] = useState<AgentOption[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<AgentOption | null>(null);
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentExecuted, setAgentExecuted] = useState(false);
  const [agentError, setAgentError] = useState<string | null>(null);

  // Tone selector (for change tone action in agent mode)
  const [tone, setTone] = useState<string>('tactical');

  // Load agents when dialog opens in agent mode
  useEffect(() => {
    if (isOpen && agentMode) {
      setAgentExecuted(false);
      setAgentLoading(false);
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
      setAgentLoading(false);
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
    setAgentLoading(true);
    setAgentExecuted(true);
    setAgentError(null);

    const prompt = buildPrompt(agentMode.action, agentMode.inputContent, agentMode.format, tone);
    callAgent(selectedAgent.slug, prompt)
      .then((result) => {
        if (result.status === 'error') {
          setAgentError(result.error ?? t_i18n('An unknown error occurred'));
          setContent('');
        } else {
          setContent(result.content);
        }
        setAgentLoading(false);
      })
      .catch((error: Error) => {
        setAgentError(error.toString());
        setContent('');
        setAgentLoading(false);
      });
  };

  const handleRefresh = () => {
    if (!selectedAgent || !agentMode) return;
    setContent('');
    setAgentExecuted(false);
    setAgentError(null);
  };

  const handleAgentChange = (_event: unknown, newValue: AgentOption | null) => {
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
      const selector = tiptapEnabled
        ? '.tiptap-editor-content.ProseMirror'
        : '.ck-content.ck-editor__editable.ck-editor__editable_inline';
      const elementEditor = document.querySelector(selector);
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
      <Autocomplete<AgentOption>
        sx={{ width: 220 }}
        size="small"
        options={agentOptions}
        getOptionLabel={(option) => option.name}
        value={selectedAgent}
        onChange={handleAgentChange}
        loading={loadingAgents}
        disabled={noAgents as boolean}
        noOptionsText={t_i18n('Ask your administrator to configure XTM One')}
        renderInput={(params) => (
          <TextField
            {...params}
            variant="outlined"
            size="small"
            placeholder={noAgents ? t_i18n('No agent available') : t_i18n('Select agent')}
            InputProps={{
              ...params.InputProps,
              endAdornment: (
                <>
                  {loadingAgents ? <CircularProgress color="inherit" size={16} /> : null}
                  {params.InputProps.endAdornment}
                </>
              ),
            }}
          />
        )}
        isOptionEqualToValue={(option, value) => option.id === value.id}
        clearIcon={null}
      />
    </Box>
  ) : t_i18n('Ask AI');

  const renderRefreshButton = () => {
    if (!agentMode) return null;
    return (
      <IconButton
        size="small"
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
      {format === 'html' && tiptapEnabled && (
        <RichTextEditor
          id="response-dialog-editor"
          data={content}
          onChange={(_, adapter) => {
            setContent(adapter.getData());
          }}
          disabled={effectiveDisabled}
        />
      )}
      {format === 'html' && !tiptapEnabled && (
        <CKEditor
          id="response-dialog-editor"
          data={content}
          onChange={(_, editor) => {
            setContent(editor.getData());
          }}
          disabled={effectiveDisabled}
          disableWatchdog={true}
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
            <FormControl size="small" fullWidth>
              <InputLabel id="tone-label">{t_i18n('Tone')}</InputLabel>
              <Select
                labelId="tone-label"
                label={t_i18n('Tone')}
                value={tone}
                onChange={(event) => setTone(event.target.value)}
                size="small"
              >
                <MenuItem value="tactical">{t_i18n('Tactical')}</MenuItem>
                <MenuItem value="operational">{t_i18n('Operational')}</MenuItem>
                <MenuItem value="strategic">{t_i18n('Strategic')}</MenuItem>
              </Select>
            </FormControl>
          </Box>
        )}

        <div style={{ width: '100%', minHeight: height, height, position: 'relative' }}>
          {agentMode && (
            <>
              {renderRefreshButton()}

              {(agentLoading || loadingAgents) && (
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

              {!agentLoading && !loadingAgents && !noAgents && !agentError && renderContentEditors()}
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
