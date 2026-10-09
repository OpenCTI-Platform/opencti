import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { Field, Form, Formik } from 'formik';
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
  SelectItem,
  SelectTrigger,
  SelectValue,
  Spinner,
  Text,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import TextField from '../../../components/TextField';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { emptyFilterGroup, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { PATH_HUNT } from '../common/routes/paths';
import HuntEntitiesField from './HuntEntitiesField';
import { mutationErrorMessage, notifyPayloadErrors, payloadErrorsMessage, useDialogMutation } from './hunt-mutation-utils';
import HuntIocFields from './HuntIocFields';
import HuntIndicatorSupportWarning from './HuntIndicatorSupportWarning';
import HuntSigmaRuleField from './HuntSigmaRuleField';
import { HuntAIAssistProvider } from './HuntAIAssist';
import type { HuntAIFormValues } from './hunt-ai-utils';
import { SIGMA_RULE_PLACEHOLDER } from './HuntCreation';
import { parseIocText } from './hunt-ioc-utils';
import { emptyHuntFormValues, HUNT_SCOPE_TYPES, huntTimeWindowPresets, type HuntFormValues, toHuntAddInput } from './hunt-utils';
import useHuntConfiguration from './useHuntConfiguration';
import { HUNT_CONNECTORS_PATH } from './HuntStatusHeader';
import { HuntGuidedCreationConnectorsQuery } from './__generated__/HuntGuidedCreationConnectorsQuery.graphql';
import { HuntGuidedCreationAddMutation, HuntGuidedCreationAddMutation$data } from './__generated__/HuntGuidedCreationAddMutation.graphql';
import { HuntGuidedCreationRunMutation } from './__generated__/HuntGuidedCreationRunMutation.graphql';
import { layerInputVars } from '../../../utils/fdsLayer';

export type HuntGuidedKind = 'indicators' | 'sigma';

const huntGuidedCreationConnectorsQuery = graphql`
  query HuntGuidedCreationConnectorsQuery {
    huntConnectors(onlyAlive: true) {
      id
      name
      platform
      supports_indicators
      securityPlatform {
        id
        name
      }
    }
  }
`;

const huntGuidedCreationAddMutation = graphql`
  mutation HuntGuidedCreationAddMutation($input: HuntAddInput!) {
    huntAdd(input: $input) {
      id
      name
      hunt_status
    }
  }
`;

const huntGuidedCreationRunMutation = graphql`
  mutation HuntGuidedCreationRunMutation($id: ID!) {
    huntRunStart(id: $id) {
      id
    }
  }
`;

const STEPS = 3;

// The guided steps show the rule, the scope and the name: the agent proposes the rule, the hypothesis, the observables and the techniques
const GUIDED_HIDDEN_AI_FIELDS: (keyof HuntAIFormValues)[] = ['description', 'benign_patterns', 'native_queries'];

/** A count of connectors holds for the scope it was counted on only: the key of a scope ignores the order of its platforms. */
const scopeKeyOf = (scopePlatformIds: string[]) => [...scopePlatformIds].sort().join(',');

/** The live hunt connectors that would run the hunt on its scope, as the readiness of the platform counts them. */
const ConnectorsForScope = ({ kind, scopePlatformIds, onCount }: {
  kind: HuntGuidedKind;
  scopePlatformIds: string[];
  onCount: (scopeKey: string, count: number) => void;
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { huntConnectors } = useLazyLoadQuery<HuntGuidedCreationConnectorsQuery>(huntGuidedCreationConnectorsQuery, {}, { fetchPolicy: 'store-and-network' });
  const eligible = huntConnectors.filter((connector) => !!connector.securityPlatform
    && (kind !== 'indicators' || connector.supports_indicators)
    && (scopePlatformIds.length === 0 || scopePlatformIds.includes(connector.securityPlatform.id)));
  const scopeKey = scopeKeyOf(scopePlatformIds);
  React.useEffect(() => onCount(scopeKey, eligible.length), [scopeKey, eligible.length]);
  if (eligible.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1), alignItems: 'flex-start' }} data-testid="hunt-guided-no-connector">
        <Text variant="content-compact" style={{ color: theme.palette.warn.main }}>
          {kind === 'indicators'
            ? t_i18n('No hunt connector of its scope supports indicator lookups: deploy one that does, such as the Splunk hunt connector')
            : t_i18n('No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope')}
        </Text>
        <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
          {t_i18n('The hunt is saved as a draft; its page lists what it still needs.')}
        </Text>
        <Button variant="tertiary" size="small" component={Link} to={HUNT_CONNECTORS_PATH}>{t_i18n('Open the hunt connectors')}</Button>
      </div>
    );
  }
  return (
    <Text variant="content-compact" data-testid="hunt-guided-connectors">
      {t_i18n('{connectors} can run it', { values: { connectors: eligible.map((connector) => `${connector.name} (${connector.securityPlatform?.name})`).join(', ') } })}
    </Text>
  );
};

interface HuntGuidedCreationProps {
  kind: HuntGuidedKind;
  open: boolean;
  onClose: () => void;
}

/**
 * A first hunt in three steps: what to look for (indicators, or a Sigma rule), where and how far back, then start. It
 * ends on the first run when a hunt connector can run it, on the hunt page and its checklist otherwise.
 */
const HuntGuidedCreation = ({ kind, open, onClose }: HuntGuidedCreationProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fd } = useFormatter();
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [connectorsLookup, setConnectorsLookup] = useState<{ scopeKey: string; count: number } | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const iocFiltersState = useFiltersState(emptyFilterGroup);
  const [commitAdd] = useDialogMutation<HuntGuidedCreationAddMutation>(huntGuidedCreationAddMutation);
  const [commitRun] = useApiMutation<HuntGuidedCreationRunMutation>(huntGuidedCreationRunMutation);
  const initialValues: HuntFormValues = {
    ...emptyHuntFormValues(),
    hunt_type: kind === 'indicators' ? 'indicators' : 'telemetry',
    name: kind === 'indicators'
      ? t_i18n('Indicator hunt - {date}', { values: { date: fd(new Date()) } })
      : t_i18n('Detection rule hunt - {date}', { values: { date: fd(new Date()) } }),
    time_window_hours: kind === 'indicators' ? 168 : 24,
  };
  // Unknown (null) until the connectors of the current scope are counted: activating or not is decided on that count only
  const connectorsCountOf = (values: HuntFormValues) => {
    const scopeKey = scopeKeyOf(values.scopePlatforms.map((platform) => platform.value));
    return connectorsLookup?.scopeKey === scopeKey ? connectorsLookup.count : null;
  };
  const close = () => {
    setStep(0);
    setConnectorsLookup(null);
    setCreateError(null);
    onClose();
  };
  const finish = (values: HuntFormValues, setSubmitting: (submitting: boolean) => void) => {
    const connectorsCount = connectorsCountOf(values);
    if (connectorsCount === null) {
      setSubmitting(false);
      return;
    }
    const runNow = connectorsCount > 0;
    const input = {
      ...toHuntAddInput({ ...values, hunt_status: runNow ? 'active' : 'draft' }, '', serializeFilterGroupForBackend(iocFiltersState[0])),
    };
    setCreateError(null);
    commitAdd({
      variables: { input },
      onCompleted: (response, errors) => {
        const errorMessage = payloadErrorsMessage(errors);
        if (errorMessage || !response.huntAdd) {
          setSubmitting(false);
          setCreateError(errorMessage ?? t_i18n('The hunt could not be created'));
          return;
        }
        const hunt = (response as HuntGuidedCreationAddMutation$data).huntAdd as { id: string };
        if (!runNow) {
          setSubmitting(false);
          MESSAGING$.notifySuccess(t_i18n('The hunt is saved as a draft; its page lists what it still needs.'));
          close();
          navigate(PATH_HUNT(hunt.id));
          return;
        }
        commitRun({
          variables: { id: hunt.id },
          onCompleted: (runResponse, runErrors) => {
            setSubmitting(false);
            close();
            if (notifyPayloadErrors(runErrors) || !runResponse.huntRunStart?.length) {
              navigate(PATH_HUNT(hunt.id));
              return;
            }
            MESSAGING$.notifySuccess(t_i18n('The hunt is active and its first run has started'));
            navigate(`${PATH_HUNT(hunt.id)}/runs/${runResponse.huntRunStart[0].id}`);
          },
          onError: () => {
            setSubmitting(false);
            close();
            navigate(PATH_HUNT(hunt.id));
          },
        });
      },
      onError: (error) => {
        setSubmitting(false);
        setCreateError(mutationErrorMessage(error, t_i18n('The hunt could not be created')));
      },
    });
  };
  const stepTitles = kind === 'indicators'
    ? [t_i18n('What to look for'), t_i18n('Where and how far back'), t_i18n('Start the hunt')]
    : [t_i18n('The detection rule'), t_i18n('Where and how far back'), t_i18n('Start the hunt')];
  const timeWindowLabel = (hours: number) => (hours === 24 ? t_i18n('The last 24 hours') : t_i18n('The last {count} days', { values: { count: String(hours / 24) } }));
  return (
    <Dialog open={open} onOpenChange={(next) => !next && close()}>
      <DialogContent size="lg" data-testid={`hunt-guided-${kind}`} style={{ ...layerInputVars } as React.CSSProperties}>
        <DialogTitle>{kind === 'indicators' ? t_i18n('Hunt for indicators') : t_i18n('Hunt with a detection rule (Sigma)')}</DialogTitle>
        <DialogDescription>
          {t_i18n('Step {step} of {count}: {title}', { values: { step: String(step + 1), count: String(STEPS), title: stepTitles[step] } })}
        </DialogDescription>
        <Formik<HuntFormValues> initialValues={initialValues} onSubmit={(values, { setSubmitting }) => finish(values, setSubmitting)}>
          {({ values, submitForm, isSubmitting }) => {
            const iocCount = parseIocText(values.ioc_values_text).values.length + values.iocElements.length + values.iocEntities.length
              + (iocFiltersState[0].filters ?? []).length;
            const connectorsCount = connectorsCountOf(values);
            return (
              <Form style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3), flex: 1, minHeight: 0 }}>
                <DialogBody>
                  <ol aria-label={t_i18n('Steps')} style={{ display: 'flex', gap: theme.spacing(2), listStyle: 'none', padding: 0, margin: `0 0 ${theme.spacing(2)} 0` }}>
                    {stepTitles.map((title, index) => (
                      <li key={title} aria-current={index === step ? 'step' : undefined}>
                        <Text variant={index === step ? 'content-compact-bold' : 'content-compact'} style={{ color: index > step ? theme.palette.text.secondary : undefined }}>
                          {`${index + 1}. ${title}`}
                        </Text>
                      </li>
                    ))}
                  </ol>
                  {step === 0 && kind === 'indicators' && (
                    <>
                      <HuntIndicatorSupportWarning scopePlatformIds={[]} style={{ marginBottom: theme.spacing(2) }} />
                      <HuntIocFields filtersState={iocFiltersState} withFilters={false} />
                    </>
                  )}
                  {step === 0 && kind === 'sigma' && (
                    <HuntAIAssistProvider hiddenFields={GUIDED_HIDDEN_AI_FIELDS} placeholderName={initialValues.name}>
                      <SigmaStep />
                    </HuntAIAssistProvider>
                  )}
                  {step === 1 && (
                    <div data-testid="hunt-guided-scope">
                      <HuntEntitiesField
                        name="scopePlatforms"
                        label={t_i18n('Security platforms (empty for all)')}
                        types={HUNT_SCOPE_TYPES}
                        helpertext={t_i18n('Where the hunt runs: its hunt connectors execute it on these platforms. Left empty, every hunt-capable platform.')}
                      />
                      <div style={{ ...fieldSpacingContainerStyle, display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }}>
                        <Text variant="content-compact">{t_i18n('Look back')}</Text>
                        <LookBackSelect value={Number(values.time_window_hours)} label={timeWindowLabel} />
                      </div>
                      <div style={fieldSpacingContainerStyle}>
                        <Suspense fallback={<Spinner size="md" label={t_i18n('Loading')} />}>
                          <ConnectorsForScope
                            kind={kind}
                            scopePlatformIds={values.scopePlatforms.map((platform) => platform.value)}
                            onCount={(scopeKey, count) => setConnectorsLookup({ scopeKey, count })}
                          />
                        </Suspense>
                      </div>
                    </div>
                  )}
                  {step === 2 && (
                    <div data-testid="hunt-guided-start">
                      <Field component={TextField} variant="outlined" name="name" label={t_i18n('Name')} fullWidth required />
                      <Text variant="content-compact" style={{ display: 'block', marginTop: theme.spacing(2) }}>
                        {(connectorsCount ?? 0) > 0
                          ? t_i18n('The hunt is created active and its first run starts right away. Its runs record what they found and a verdict.')
                          : t_i18n('No hunt connector can run it yet: the hunt is saved as a draft and its page lists what it still needs.')}
                      </Text>
                    </div>
                  )}
                  {createError && (
                    <div style={{ marginTop: theme.spacing(2) }} role="alert">
                      <Alert severity="error" title={t_i18n('The hunt could not be created')} description={createError} data-testid="hunt-guided-error" />
                    </div>
                  )}
                </DialogBody>
                <DialogFooter>
                  <Button variant="secondary" onClick={() => (step === 0 ? close() : setStep(step - 1))} disabled={isSubmitting}>
                    {step === 0 ? t_i18n('Cancel') : t_i18n('Back')}
                  </Button>
                  {step < STEPS - 1 ? (
                    <Button
                      onClick={() => setStep(step + 1)}
                      disabled={(step === 0 && (kind === 'indicators' ? iocCount === 0 : values.sigma_rule.trim().length === 0))
                        || (step === 1 && connectorsCount === null)}
                      data-testid="hunt-guided-next"
                    >
                      {t_i18n('Next')}
                    </Button>
                  ) : (
                    <Button
                      onClick={submitForm}
                      disabled={isSubmitting || connectorsCount === null || values.name.trim().length < 2}
                      data-testid="hunt-guided-submit"
                    >
                      {(connectorsCount ?? 0) > 0 ? t_i18n('Activate and run now') : t_i18n('Save as a draft')}
                    </Button>
                  )}
                  {step === 0 && (kind === 'indicators' ? iocCount === 0 : values.sigma_rule.trim().length === 0) && (
                    <Text variant="content-caption" style={{ color: theme.palette.text.secondary }} data-testid="hunt-guided-next-reason">
                      {kind === 'indicators' ? t_i18n('Add the indicators or observables to look for') : t_i18n('Add a Sigma rule or a native query')}
                    </Text>
                  )}
                </DialogFooter>
              </Form>
            );
          }}
        </Formik>
      </DialogContent>
    </Dialog>
  );
};

const SigmaStep = () => {
  const { t_i18n } = useFormatter();
  return (
    <div data-testid="hunt-guided-sigma">
      <HuntSigmaRuleField
        label={t_i18n('Sigma rule (YAML)')}
        helperText={t_i18n('Paste a rule from SigmaHQ or your own: the hunt connector translates it for your SIEM or EDR.')}
        placeholder={SIGMA_RULE_PLACEHOLDER}
        minRows={12}
        testId="hunt-guided-sigma-editor"
      />
    </div>
  );
};

const LookBackSelect = ({ value, label }: { value: number; label: (hours: number) => string }) => {
  const { t_i18n } = useFormatter();
  const { maxTimeWindowHours } = useHuntConfiguration();
  return (
    <Field name="time_window_hours">
      {({ form }: { form: { setFieldValue: (field: string, next: number) => void } }) => (
        <Select value={String(value)} onValueChange={(next) => form.setFieldValue('time_window_hours', Number(next))}>
          <SelectTrigger aria-label={t_i18n('Look back')} style={{ minWidth: 240 }} data-testid="hunt-guided-time-window">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Look back')}>
            {huntTimeWindowPresets(maxTimeWindowHours).map((hours) => <SelectItem key={hours} value={String(hours)}>{label(hours)}</SelectItem>)}
          </SelectContent>
        </Select>
      )}
    </Field>
  );
};

export default HuntGuidedCreation;
