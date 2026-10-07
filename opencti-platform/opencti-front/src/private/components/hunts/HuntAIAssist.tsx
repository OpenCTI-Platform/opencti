import React, { createContext, ReactNode, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import type { Disposable, PayloadError } from 'relay-runtime';
import { Link } from 'react-router';
import { useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import {
  Alert,
  Checkbox,
  Chip,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
  Input,
  Spinner,
  Text,
  Textarea,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import type { RelayError } from '../../../relay/relayTypes';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import HuntCodeEditor from './HuntCodeEditor';
import { XTM_ONE_SETTINGS_PATH } from './HuntsSetupChecklist';
import useHuntAI from './useHuntAI';
import {
  HUNT_AI_FAILURE_TEXT,
  huntAIAcceptedChanges,
  type HuntAIEdits,
  huntAIFailureOf,
  huntAIFailureOpensSettings,
  type HuntAIFailure,
  type HuntAIFormValues,
  huntAIHasSubject,
  type HuntAIPart,
  huntAIPartReplaces,
  type HuntAIProposal,
  huntAIProposalParts,
  type HuntAIRequest,
  huntAssistInput,
  huntTechniqueOption,
} from './hunt-ai-utils';
import { HuntAIAssistMutation } from './__generated__/HuntAIAssistMutation.graphql';

export const huntAIAssistMutation = graphql`
  mutation HuntAIAssistMutation($input: HuntAssistInput!) {
    huntAssist(input: $input) {
      fields
      name
      hypothesis
      description
      sigma_rule
      native_queries {
        platform
        language
        query
        pipeline
      }
      expected_observables
      benign_patterns
      techniques {
        id
        entity_type
        name
        x_mitre_id
      }
      unknown_technique_ids
      rationale
    }
  }
`;

interface HuntAIContextValue {
  open: (request: HuntAIRequest) => void;
  /** The form header carries the "not configured" reason once: the field actions only repeat it in a tooltip */
  reasonInHeader: boolean;
}

const HuntAIContext = createContext<HuntAIContextValue | null>(null);

const DIALOG_TITLES: Record<HuntAIRequest['kind'], string> = {
  plan: 'Plan the hunt with AI',
  hypothesis: 'Write the hypothesis with AI',
  description: 'Write the description with AI',
  sigma_rule: 'Write the Sigma rule with AI',
  native_queries: 'Write the native query with AI',
  expected_observables: 'Propose the observables to extract with AI',
  benign_patterns: 'Propose benign patterns with AI',
};

const PROGRESS_LINES: Record<HuntAIRequest['kind'], string> = {
  plan: 'XTM One is writing the plan from the form and the platform knowledge',
  hypothesis: 'XTM One is writing the hypothesis from the form and the platform knowledge',
  description: 'XTM One is writing the description from the form and the platform knowledge',
  sigma_rule: 'XTM One is writing the Sigma rule from the form and the platform knowledge',
  native_queries: 'XTM One is writing the native query from the form and the platform knowledge',
  expected_observables: 'XTM One is choosing the observables to extract from the form',
  benign_patterns: 'XTM One is listing benign patterns from the form and the platform knowledge',
};

const PART_LABELS: Record<Exclude<HuntAIPart, `technique:${string}`>, string> = {
  name: 'Name',
  hypothesis: 'Hypothesis',
  description: 'Description',
  sigma_rule: 'Sigma rule',
  native_queries: 'Native queries',
  expected_observables: 'Observables to extract from hits',
  benign_patterns: 'Benign patterns',
};

const isTechniquePart = (part: HuntAIPart): part is `technique:${string}` => part.startsWith('technique:');

interface HuntAIFormScope {
  /** The saved hunt, whose fields complete the ones the form does not hold */
  huntId?: string;
  /** Fields the form holds without showing them: they are neither sent nor proposed */
  hiddenFields?: (keyof HuntAIFormValues)[];
  /** A name the form fills by default, which says nothing about what to hunt */
  placeholderName?: string;
}

interface HuntAIAssistProviderProps extends HuntAIFormScope {
  reasonInHeader?: boolean;
  children: ReactNode;
}

/** The values of the form as the assistance reads them. */
const scopedValues = (values: HuntAIFormValues, { hiddenFields = [], placeholderName }: HuntAIFormScope): HuntAIFormValues => {
  const scoped: HuntAIFormValues = { ...values };
  hiddenFields.forEach((field) => {
    delete scoped[field];
  });
  if (placeholderName && scoped.name === placeholderName) {
    scoped.name = '';
  }
  return scoped;
};

/**
 * The AI assistance of a hunt form: every "Generate with AI" of the form and its "Plan with AI" open the same
 * proposal dialog, which reads the whole form and writes nothing until the analyst accepts. Renders inside Formik.
 */
export const HuntAIAssistProvider = ({ huntId, hiddenFields, placeholderName, reasonInHeader = false, children }: HuntAIAssistProviderProps) => {
  const [request, setRequest] = useState<HuntAIRequest | null>(null);
  const value = useMemo(() => ({ open: setRequest, reasonInHeader }), [reasonInHeader]);
  return (
    <HuntAIContext.Provider value={value}>
      {children}
      {request && <HuntAIProposalDialog request={request} scope={{ huntId, hiddenFields, placeholderName }} onClose={() => setRequest(null)} />}
    </HuntAIContext.Provider>
  );
};

interface HuntAIActionProps {
  request: HuntAIRequest;
  /** Defaults to "Generate with AI" */
  label?: string;
  disabled?: boolean;
  testId: string;
}

/**
 * The "Generate with AI" of a hunt form field, on its label row (or "Plan with AI" in the form header): enabled
 * whenever XTM One is configured; otherwise disabled with the reason and where to configure it.
 */
export const HuntAIAction = ({ request, label, disabled = false, testId }: HuntAIActionProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const context = useContext(HuntAIContext);
  const { isEnterpriseEdition, xtmOneConfigured } = useHuntAI();
  const canSetParameters = useGranted([SETTINGS_SETPARAMETERS]);
  if (!context) {
    return null;
  }
  const text = label ?? t_i18n('Generate with AI');
  const button = (
    <Button
      variant="tertiary"
      size="small"
      startIcon={<AutoAwesomeOutlined fontSize="small" />}
      onClick={() => context.open(request)}
      disabled={disabled || !isEnterpriseEdition || !xtmOneConfigured}
      data-testid={testId}
    >
      {text}
    </Button>
  );
  if (!isEnterpriseEdition) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        {button}
        <EEChip feature={text} size="sm" style={{ marginInlineStart: 0 }} />
      </div>
    );
  }
  if (xtmOneConfigured) {
    return button;
  }
  const reason = t_i18n('XTM One is not configured on this platform');
  if (context.reasonInHeader && request.kind !== 'plan') {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          {/* A disabled button receives no pointer or focus events: its wrapper carries the reason, and the focus ring of
              the button with its rounded-sm radius */}
          <span
            tabIndex={0}
            aria-label={`${text} - ${reason}`}
            className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
            data-testid={`${testId}-unavailable`}
          >
            {button}
          </span>
        </TooltipTrigger>
        <TooltipContent>{reason}</TooltipContent>
      </Tooltip>
    );
  }
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0 }}>
      <Text variant="content-caption" style={{ color: theme.palette.text.secondary, whiteSpace: 'nowrap' }} data-testid={`${testId}-reason`}>
        {reason}
      </Text>
      {canSetParameters ? (
        <Button variant="tertiary" size="small" component={Link} to={XTM_ONE_SETTINGS_PATH} data-testid={`${testId}-settings`}>
          {t_i18n('Open the settings')}
        </Button>
      ) : (
        <Text variant="content-caption" style={{ color: theme.palette.text.secondary, whiteSpace: 'nowrap' }}>{t_i18n('Ask your administrator')}</Text>
      )}
      {button}
    </div>
  );
};

/** "Plan with AI" of a hunt form header: the whole plan as one proposal. */
export const HuntPlanWithAIAction = ({ disabled }: { disabled?: boolean }) => {
  const { t_i18n } = useFormatter();
  return <HuntAIAction request={{ kind: 'plan' }} label={t_i18n('Plan with AI')} disabled={disabled} testId="hunt-ai-plan" />;
};

type Phase = 'prompt' | 'running' | 'proposal' | 'error';

interface HuntAIProposalDialogProps {
  request: HuntAIRequest;
  scope: HuntAIFormScope;
  onClose: () => void;
}

const HuntAIProposalDialog = ({ request, scope, onClose }: HuntAIProposalDialogProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const canSetParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const { values: formValues, setFieldValue } = useFormikContext<HuntAIFormValues>();
  const values = scopedValues(formValues, scope);
  const { huntId } = scope;
  const needsPrompt = !huntAIHasSubject(values, huntId);
  const [phase, setPhase] = useState<Phase>(needsPrompt ? 'prompt' : 'running');
  const [prompt, setPrompt] = useState('');
  const [promptError, setPromptError] = useState<string | null>(null);
  const [proposal, setProposal] = useState<HuntAIProposal | null>(null);
  const [failure, setFailure] = useState<{ failure: HuntAIFailure; message: string } | null>(null);
  const [accepted, setAccepted] = useState<HuntAIPart[]>([]);
  const [edits, setEdits] = useState<HuntAIEdits>({});
  const [elapsed, setElapsed] = useState(0);
  const inFlight = useRef<Disposable | null>(null);
  const [commit] = useMutation<HuntAIAssistMutation>(huntAIAssistMutation);
  const fallback = t_i18n('XTM One could not write the proposal');

  const generate = () => {
    if (needsPrompt && prompt.trim().length === 0) {
      setPromptError(t_i18n('Say in a few words what to hunt'));
      return;
    }
    setPromptError(null);
    setFailure(null);
    setElapsed(0);
    setPhase('running');
    inFlight.current?.dispose();
    inFlight.current = commit({
      variables: { input: huntAssistInput(values, request, { huntId, prompt }) },
      onCompleted: (data, errors) => {
        inFlight.current = null;
        if ((errors ?? []).length > 0 || !data.huntAssist) {
          setFailure(huntAIFailureOf(errors, fallback));
          setPhase('error');
          return;
        }
        const next = data.huntAssist as HuntAIProposal;
        const { primary } = huntAIProposalParts(next, values, request);
        // A plan leaves out, until checked, what would replace the analyst's own text
        setAccepted(request.kind === 'plan' ? primary.filter((part) => !huntAIPartReplaces(values, part, request)) : primary);
        setEdits({});
        setProposal(next);
        setPhase('proposal');
      },
      onError: (error) => {
        inFlight.current = null;
        // The platform network layer attaches the GraphQL errors as `res`, Relay itself as `source` when no data came back
        const relayError = error as unknown as Partial<RelayError> & { source?: { errors?: PayloadError[] } };
        setFailure(huntAIFailureOf(relayError.res?.errors ?? relayError.source?.errors, fallback));
        setPhase('error');
      },
    });
  };

  useEffect(() => {
    if (!needsPrompt) {
      generate();
    }
    return () => inFlight.current?.dispose();
  }, []);

  useEffect(() => {
    if (phase !== 'running') return undefined;
    const timer = setInterval(() => setElapsed((seconds) => seconds + 1), 1000);
    return () => clearInterval(timer);
  }, [phase]);

  const cancel = () => {
    inFlight.current?.dispose();
    inFlight.current = null;
    onClose();
  };

  const accept = () => {
    if (proposal) {
      huntAIAcceptedChanges(proposal, values, request, accepted, edits).forEach(([field, value]) => setFieldValue(field, value));
    }
    onClose();
  };

  const toggle = (part: HuntAIPart) => setAccepted((current) => (current.includes(part) ? current.filter((item) => item !== part) : [...current, part]));

  const partLabel = (part: HuntAIPart) => {
    if (isTechniquePart(part)) {
      const technique = proposal?.techniques.find((item) => `technique:${item.id}` === part);
      return technique ? String(huntTechniqueOption(technique).label) : part;
    }
    return t_i18n(PART_LABELS[part]);
  };

  const renderPartEditor = (part: Exclude<HuntAIPart, `technique:${string}`>, current: HuntAIProposal) => {
    const rowLanguage = request.kind === 'native_queries' ? (values.native_queries ?? [])[request.nativeQueryIndex ?? 0]?.language : null;
    // In a plan, the box of each part already names it
    const named = request.kind === 'plan';
    switch (part) {
      case 'sigma_rule':
        return <HuntCodeEditor label={t_i18n('Sigma rule (YAML)')} hideLabel={named} language="yaml" value={edits.sigma_rule ?? current.sigma_rule} onChange={(next) => setEdits({ ...edits, sigma_rule: next })} minRows={8} maxRows={18} testId="hunt-ai-proposal-sigma_rule" />;
      case 'native_queries':
        if (request.kind === 'native_queries') {
          return <HuntCodeEditor label={t_i18n('Query')} language={rowLanguage} value={edits.native_query ?? current.native_queries[0]?.query ?? ''} onChange={(next) => setEdits({ ...edits, native_query: next })} minRows={4} maxRows={14} testId="hunt-ai-proposal-native_queries" />;
        }
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
            {current.native_queries.map((query) => (
              <HuntCodeEditor key={query.platform} label={`${query.platform} (${query.language})`} language={query.language} value={query.query} onChange={() => undefined} disabled minRows={2} maxRows={8} />
            ))}
          </div>
        );
      case 'expected_observables': {
        const types = edits.expected_observables ?? [...current.expected_observables];
        return (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(1) }} data-testid="hunt-ai-proposal-expected_observables">
            {types.map((type) => (
              <Chip key={type} label={t_i18n(`entity_${type}`)} onDelete={() => setEdits({ ...edits, expected_observables: types.filter((item) => item !== type) })} />
            ))}
          </div>
        );
      }
      case 'benign_patterns':
        return <Textarea aria-label={t_i18n(PART_LABELS[part])} value={edits.benign_patterns ?? current.benign_patterns.join('\n')} onChange={(event) => setEdits({ ...edits, benign_patterns: event.target.value })} rows={4} data-testid="hunt-ai-proposal-benign_patterns" />;
      default:
        return <Textarea aria-label={t_i18n(PART_LABELS[part])} value={edits[part] ?? current[part]} onChange={(event) => setEdits({ ...edits, [part]: event.target.value })} rows={part === 'name' ? 1 : 4} data-testid={`hunt-ai-proposal-${part}`} />;
    }
  };

  const renderProposal = (current: HuntAIProposal) => {
    const { primary, secondary } = huntAIProposalParts(current, values, request);
    const textParts = primary.filter((part): part is Exclude<HuntAIPart, `technique:${string}`> => !isTechniquePart(part));
    const techniqueParts = primary.filter(isTechniquePart);
    const isPlan = request.kind === 'plan';
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }} data-testid="hunt-ai-proposal">
        {textParts.map((part) => (
          <div key={part} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }}>
            {isPlan ? (
              <Checkbox
                checked={accepted.includes(part)}
                onCheckedChange={() => toggle(part)}
                label={t_i18n(PART_LABELS[part])}
                description={huntAIPartReplaces(values, part, request) ? t_i18n('Replaces what the form holds') : undefined}
                data-testid={`hunt-ai-use-${part}`}
              />
            ) : (
              huntAIPartReplaces(values, part, request) && (
                <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Replaces what the form holds')}</Text>
              )
            )}
            {renderPartEditor(part, current)}
          </div>
        ))}
        {techniqueParts.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
            <Text variant="content-compact-medium">{t_i18n('Covered techniques')}</Text>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(1) }}>
              {techniqueParts.map((part) => (
                <Chip key={part} label={partLabel(part)} severity={accepted.includes(part) ? 'info' : 'neutral'} onClick={() => toggle(part)} aria-pressed={accepted.includes(part)} />
              ))}
            </div>
          </div>
        )}
        {secondary.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: theme.spacing(1) }} data-testid="hunt-ai-secondary">
            <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Also add')}</Text>
            {secondary.map((part) => (
              <Chip
                key={part}
                label={partLabel(part)}
                severity={accepted.includes(part) ? 'info' : 'neutral'}
                onClick={() => toggle(part)}
                aria-pressed={accepted.includes(part)}
                title={!isTechniquePart(part) && typeof current[part as keyof HuntAIProposal] === 'string' ? String(current[part as keyof HuntAIProposal]).substring(0, 300) : undefined}
                data-testid={`hunt-ai-secondary-${part}`}
              />
            ))}
          </div>
        )}
        {current.rationale && (
          <Text
            variant="content-caption"
            title={current.rationale}
            style={{ display: 'block', color: theme.palette.text.secondary, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
            data-testid="hunt-ai-rationale"
          >
            {current.rationale}
          </Text>
        )}
        {current.unknown_technique_ids.length > 0 && (
          <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary }}>
            {t_i18n('Techniques not on this platform: {ids}', { values: { ids: current.unknown_technique_ids.join(', ') } })}
          </Text>
        )}
      </div>
    );
  };

  const renderBody = () => {
    switch (phase) {
      case 'prompt':
        return (
          <Input
            label={t_i18n('What do you want to hunt?')}
            placeholder={t_i18n('For example: Office documents launching encoded PowerShell')}
            helperText={promptError ?? t_i18n('XTM One writes the proposal from your words and the knowledge on this platform.')}
            error={promptError ?? undefined}
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                generate();
              }
            }}
            autoFocus
            data-testid="hunt-ai-prompt"
          />
        );
      case 'running':
        return (
          <div role="status" aria-live="polite" style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0 }} data-testid="hunt-ai-progress">
            <Spinner size="sm" />
            <Text variant="content-compact" style={{ flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={t_i18n(PROGRESS_LINES[request.kind])}>
              {t_i18n(PROGRESS_LINES[request.kind])}
            </Text>
            <Text variant="content-caption" style={{ color: theme.palette.text.secondary, whiteSpace: 'nowrap' }}>
              {t_i18n('{seconds} s', { values: { seconds: String(elapsed) } })}
            </Text>
          </div>
        );
      case 'error': {
        const text = HUNT_AI_FAILURE_TEXT[failure?.failure ?? 'UNKNOWN'];
        return (
          <div role="alert" style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
            <Alert
              severity="error"
              title={t_i18n(text.title)}
              description={t_i18n(text.description)}
              action={failure && huntAIFailureOpensSettings(failure.failure) && canSetParameters ? (
                <Button variant="secondary" size="small" component={Link} to={XTM_ONE_SETTINGS_PATH} data-testid="hunt-ai-error-settings">
                  {t_i18n('Open the settings')}
                </Button>
              ) : undefined}
              data-testid="hunt-ai-error"
            />
            {/* The details add what the platform or XTM One said beyond the cause (a quota, the checks an answer failed) */}
            {failure?.message && (failure.failure === 'UNKNOWN' || failure.message.includes(': ')) && (
              <Text variant="content-caption" style={{ color: theme.palette.text.secondary }} data-testid="hunt-ai-error-details">
                {t_i18n('Details: {message}', { values: { message: failure.message } })}
              </Text>
            )}
          </div>
        );
      }
      default:
        return proposal ? renderProposal(proposal) : null;
    }
  };

  const renderFooter = () => {
    switch (phase) {
      case 'prompt':
        return (
          <>
            <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
            <Button intent="ai" onClick={generate} data-testid="hunt-ai-generate">{t_i18n('Generate')}</Button>
          </>
        );
      case 'running':
        return <Button variant="secondary" onClick={cancel} data-testid="hunt-ai-cancel">{t_i18n('Cancel')}</Button>;
      case 'error':
        return (
          <>
            <Button variant="secondary" onClick={onClose}>{t_i18n('Close')}</Button>
            <Button intent="ai" onClick={generate} data-testid="hunt-ai-retry">{t_i18n('Retry')}</Button>
          </>
        );
      default:
        return (
          <>
            <Button variant="secondary" onClick={onClose} data-testid="hunt-ai-dismiss">{t_i18n('Dismiss')}</Button>
            <Button variant="secondary" startIcon={<AutoAwesomeOutlined fontSize="small" />} onClick={generate} data-testid="hunt-ai-regenerate">{t_i18n('Regenerate')}</Button>
            <Button onClick={accept} data-testid="hunt-ai-accept">{t_i18n('Accept')}</Button>
          </>
        );
    }
  };

  return (
    <Dialog open onOpenChange={(next) => !next && cancel()}>
      <DialogContent size={request.kind === 'plan' ? 'lg' : 'md'} data-testid="hunt-ai-dialog">
        <DialogTitle>{t_i18n(DIALOG_TITLES[request.kind])}</DialogTitle>
        <DialogDescription>{t_i18n('Nothing changes in the form until you accept.')}</DialogDescription>
        <DialogBody>{renderBody()}</DialogBody>
        <DialogFooter>{renderFooter()}</DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
