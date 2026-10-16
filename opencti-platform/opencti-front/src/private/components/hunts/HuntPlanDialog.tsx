import React, { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { Formik, useFormikContext } from 'formik';
import { useNavigate } from 'react-router';
import { useTheme } from '@mui/styles';
import {
  Alert,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
  Select,
  SelectContent,
  SelectHelperText,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Spinner,
  Text,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import CodeBlock from '@components/common/CodeBlock';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { mutationErrorMessage, payloadErrorsMessage, useDialogMutation } from './hunt-mutation-utils';
import { AgentOption, fetchAgentsForIntent } from '../../../utils/ai/agentApi';
import HuntEntitiesField from './HuntEntitiesField';
import { HUNT_DIALOG_BODY_STYLE } from './hunt-layout-utils';
import {
  HUNT_PLANNER_INTENT,
  HUNT_SOURCE_TYPES,
  HUNT_TARGET_TYPES,
  HUNT_TECHNIQUE_TYPES,
  huntDraftWorkspacePath,
  huntPlatformLabel,
  huntQueryLanguageLabel,
  huntTypeLabel,
} from './hunt-utils';
import { prismLanguageOf } from './HuntCodeEditor';
import { HuntPlanDialogMutation, HuntPlanDialogMutation$data } from './__generated__/HuntPlanDialogMutation.graphql';
import { layerInputVars } from '../../../utils/fdsLayer';

const PLAN_SUBJECT_TYPES = [...HUNT_TARGET_TYPES, ...HUNT_TECHNIQUE_TYPES, ...HUNT_SOURCE_TYPES];

interface PlanSubjectsValues {
  subjects: { value: string }[];
}

const PlanSubjectsSync = ({ onChange }: { onChange: (ids: string[]) => void }) => {
  const { values } = useFormikContext<PlanSubjectsValues>();
  useEffect(() => {
    onChange((values.subjects ?? []).map((subject) => subject.value));
  }, [values.subjects]);
  return null;
};

const huntPlanDialogMutation = graphql`
  mutation HuntPlanDialogMutation($input: HuntPlanInput!) {
    huntPlan(input: $input) {
      draft_id
      hunt {
        id
        name
        hypothesis
        hunt_type
        sigma_rule
        native_queries {
          platform
          language
          query
        }
      }
    }
  }
`;

const DEFAULT_AGENT = '__default__';

type HuntProposal = NonNullable<HuntPlanDialogMutation$data['huntPlan']>;

interface HuntPlanDialogProps {
  open: boolean;
  onClose: () => void;
  /** Entities the hunt is planned from (the backend expands Reports and PIRs to their threats and techniques); when empty the analyst picks them */
  entityIds: string[];
}

/** Asks an XTM One agent to plan a hunt; the proposal lands in a draft workspace the analyst reviews. */
const HuntPlanDialog = ({ open, onClose, entityIds }: HuntPlanDialogProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [agents, setAgents] = useState<AgentOption[] | null>(null);
  const [agentSlug, setAgentSlug] = useState<string>(DEFAULT_AGENT);
  const [proposal, setProposal] = useState<HuntProposal | null>(null);
  const [pickedIds, setPickedIds] = useState<string[]>([]);
  const [planError, setPlanError] = useState<string | null>(null);
  const [commit, inFlight] = useDialogMutation<HuntPlanDialogMutation>(huntPlanDialogMutation);
  const picksSubjects = entityIds.length === 0;
  const subjectIds = picksSubjects ? pickedIds : entityIds;

  useEffect(() => {
    if (!open) return undefined;
    let active = true;
    setProposal(null);
    setPickedIds([]);
    setPlanError(null);
    fetchAgentsForIntent(HUNT_PLANNER_INTENT).then((options) => {
      if (active) setAgents(options);
    });
    return () => {
      active = false;
    };
  }, [open]);

  const plan = () => {
    setPlanError(null);
    commit({
      variables: {
        input: {
          entity_ids: subjectIds,
          agent_slug: agentSlug === DEFAULT_AGENT ? null : agentSlug,
        },
      },
      onCompleted: (data, errors) => {
        const errorMessage = payloadErrorsMessage(errors);
        if (errorMessage) {
          setPlanError(errorMessage);
          return;
        }
        setProposal(data.huntPlan ?? null);
      },
      onError: (error) => setPlanError(mutationErrorMessage(error, t_i18n('The agent could not plan the hunt'))),
    });
  };

  const reviewDraft = () => {
    if (!proposal) return;
    onClose();
    navigate(huntDraftWorkspacePath(proposal.draft_id));
  };

  const renderProposal = (current: HuntProposal) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }} data-testid="hunt-plan-proposal">
      <Text variant="content-compact">
        {t_i18n('The proposed hunt was created in a draft workspace. Review it, then validate the draft to make it available.')}
      </Text>
      {current.hunt && (
        <>
          <div>
            <Text variant="content-compact-bold">{t_i18n('Name')}</Text>
            <Text variant="content-compact">{current.hunt.name}</Text>
          </div>
          <div>
            <Text variant="content-compact-bold">{t_i18n('Hunt type')}</Text>
            <Text variant="content-compact">{t_i18n(huntTypeLabel(current.hunt.hunt_type))}</Text>
          </div>
          {current.hunt.hypothesis && (
            <div>
              <Text variant="content-compact-bold">{t_i18n('Hypothesis')}</Text>
              <Text variant="content-compact">{current.hunt.hypothesis}</Text>
            </div>
          )}
          {current.hunt.sigma_rule && (
            <div>
              <Text variant="content-compact-bold">{t_i18n('Sigma rule')}</Text>
              <CodeBlock language="yaml" code={current.hunt.sigma_rule} customHeight="240px" />
            </div>
          )}
          {(current.hunt.native_queries ?? []).length > 0 && (
            <div data-testid="hunt-plan-native-queries">
              <Text variant="content-compact-bold">{t_i18n('Native queries')}</Text>
              <Text variant="content-compact">{t_i18n('Native queries override the Sigma translation on their platform.')}</Text>
              {(current.hunt.native_queries ?? []).map((nativeQuery) => (
                <div key={`${nativeQuery.platform}-${nativeQuery.language}`} style={{ marginTop: theme.spacing(1) }}>
                  <Text variant="content-compact">{`${huntPlatformLabel(nativeQuery.platform, t_i18n)} - ${huntQueryLanguageLabel(nativeQuery.language, t_i18n)}`}</Text>
                  <CodeBlock language={prismLanguageOf(nativeQuery.language)} code={nativeQuery.query} customHeight="auto" wrapLongLines showLineNumbers={false} />
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );

  const renderForm = () => {
    if (agents === null) {
      return <Spinner size="md" label={t_i18n('Loading')} />;
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        {picksSubjects && (
          <Formik<PlanSubjectsValues> initialValues={{ subjects: [] }} onSubmit={() => undefined}>
            <div data-testid="hunt-plan-subjects">
              <HuntEntitiesField
                name="subjects"
                label={t_i18n('Plan from (threats, techniques, reports or indicators)')}
                types={PLAN_SUBJECT_TYPES}
                helpertext={t_i18n('Pick at least one threat, technique, report or indicator')}
              />
              <PlanSubjectsSync onChange={setPickedIds} />
            </div>
          </Formik>
        )}
        {/* Select renders no box of its own: the wrapper keeps the label, trigger and helper spacing of the library */}
        <div>
          <Select value={agentSlug} onValueChange={setAgentSlug}>
            <SelectLabel>{t_i18n('Agent')}</SelectLabel>
            <SelectTrigger className="w-full" data-testid="hunt-plan-agent">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Agent')}>
              <SelectItem value={DEFAULT_AGENT}>{t_i18n('Default hunt planner')}</SelectItem>
              {agents.map((agent) => (
                <SelectItem key={agent.slug} value={agent.slug}>{agent.name}</SelectItem>
              ))}
            </SelectContent>
            <SelectHelperText>
              {t_i18n('From the knowledge you pick, the default hunt planner writes a falsifiable hypothesis, a Sigma rule and the observables to extract.')}
            </SelectHelperText>
          </Select>
        </div>
        {inFlight && <Spinner size="md" label={t_i18n('The agent is planning the hunt')} />}
        {planError && (
          <div role="alert">
            <Alert severity="error" title={t_i18n('The agent could not plan the hunt')} description={planError} data-testid="hunt-plan-error" />
          </div>
        )}
      </div>
    );
  };

  return (
    <Dialog open={open} onOpenChange={(value) => !value && onClose()}>
      <DialogContent size="md" data-testid="hunt-plan-dialog" style={{ ...layerInputVars } as React.CSSProperties}>
        <DialogTitle>{t_i18n('Plan a hunt with AI')}</DialogTitle>
        <DialogDescription>
          {t_i18n('An XTM One agent writes a hypothesis and the hunt logic from this knowledge. Nothing runs before you validate the draft.')}
        </DialogDescription>
        <DialogBody style={HUNT_DIALOG_BODY_STYLE}>
          {proposal ? renderProposal(proposal) : renderForm()}
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={inFlight}>
            {proposal ? t_i18n('Close') : t_i18n('Cancel')}
          </Button>
          {proposal ? (
            <Button onClick={reviewDraft} data-testid="hunt-plan-review">
              {t_i18n('Review the draft')}
            </Button>
          ) : (
            <Button onClick={plan} disabled={inFlight || agents === null || subjectIds.length === 0} data-testid="hunt-plan-submit">
              {t_i18n('Plan the hunt')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default HuntPlanDialog;
