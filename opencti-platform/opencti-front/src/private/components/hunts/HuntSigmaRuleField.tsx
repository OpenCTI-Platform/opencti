import React, { ReactNode, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { Field, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import { Alert, Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import { HuntCodeEditorField } from './HuntCodeEditor';
import { XTM_ONE_SETTINGS_PATH } from './HuntsSetupChecklist';
import HuntSigmaValidation from './HuntSigmaValidation';
import { mutationErrorMessage, payloadErrorsMessage } from './hunt-mutation-utils';
import useHuntAI from './useHuntAI';
import { HuntSigmaRuleFieldGenerateMutation, HuntSigmaRuleFieldGenerateMutation$variables } from './__generated__/HuntSigmaRuleFieldGenerateMutation.graphql';

export const huntSigmaRuleFieldGenerateMutation = graphql`
  mutation HuntSigmaRuleFieldGenerateMutation($input: HuntSigmaGenerateInput!) {
    huntSigmaGenerate(input: $input) {
      sigma_rule
      rationale
    }
  }
`;

export type HuntSigmaGenerationInput = HuntSigmaRuleFieldGenerateMutation$variables['input'];

/** Whether the hunt carries something a Sigma rule can be generated from: its hypothesis, threats or techniques, or the saved hunt. */
export const canGenerateSigmaFrom = (input: HuntSigmaGenerationInput) => !!input.hunt_id
  || (input.hypothesis ?? '').trim().length > 0
  || (input.target_ids ?? []).length > 0
  || (input.technique_ids ?? []).length > 0;

interface GeneratedRule {
  previous: string;
  generated: string;
  rationale: string | null;
}

interface SigmaRuleValues {
  sigma_rule: string;
}

interface HuntSigmaRuleFieldProps {
  label: string;
  helperText: string;
  placeholder: string;
  /** What the rule is generated from: the fields of the hunt being written, or the saved hunt */
  generationInput: HuntSigmaGenerationInput;
  /** What to do with a generated rule once it is in the editor, next to its undo */
  nextStep?: { sentence: string; action?: ReactNode };
  minRows?: number;
  maxRows?: number;
  disabled?: boolean;
  testId: string;
}

/**
 * The Sigma rule of a hunt: its editor, with "Generate with AI" in the label row (the rule is written by XTM One from
 * the hunt and lands in the editor with an undo), and the live validation of the platform under it.
 */
const HuntSigmaRuleField = ({ label, helperText, placeholder, generationInput, nextStep, minRows = 10, maxRows, disabled = false, testId }: HuntSigmaRuleFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { isEnterpriseEdition, xtmOneConfigured } = useHuntAI();
  const canSetParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const { values, setFieldValue } = useFormikContext<SigmaRuleValues>();
  const [commit, inFlight] = useApiMutation<HuntSigmaRuleFieldGenerateMutation>(huntSigmaRuleFieldGenerateMutation);
  const [applied, setApplied] = useState<GeneratedRule | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sigmaRule = values.sigma_rule ?? '';

  // Once the analyst edits the generated rule, undoing would discard the edits
  useEffect(() => {
    if (applied && sigmaRule !== applied.generated) {
      setApplied(null);
    }
  }, [sigmaRule]);

  let reason: string | null = null;
  if (isEnterpriseEdition && !xtmOneConfigured) {
    reason = t_i18n('XTM One is not configured on this platform');
  } else if (isEnterpriseEdition && !canGenerateSigmaFrom(generationInput)) {
    reason = t_i18n('Write the hypothesis or add a threat or a technique first');
  }
  const unavailable = !isEnterpriseEdition || reason !== null;

  const generate = () => {
    setError(null);
    const previous = sigmaRule;
    commit({
      variables: { input: { ...generationInput, sigma_rule: previous } },
      onCompleted: (data, errors) => {
        const errorMessage = payloadErrorsMessage(errors);
        if (errorMessage || !data.huntSigmaGenerate) {
          setError(errorMessage ?? t_i18n('The Sigma rule could not be generated'));
          return;
        }
        const generated = data.huntSigmaGenerate.sigma_rule;
        setFieldValue('sigma_rule', generated);
        setApplied({ previous, generated, rationale: data.huntSigmaGenerate.rationale ?? null });
      },
      onError: (mutationError) => setError(mutationErrorMessage(mutationError, t_i18n('The Sigma rule could not be generated'))),
    });
  };

  const undo = () => {
    if (!applied) return;
    setFieldValue('sigma_rule', applied.previous);
    setApplied(null);
  };

  const xtmOneMissing = isEnterpriseEdition && !xtmOneConfigured;
  const action = (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      {reason && (
        <Text variant="content-caption" style={{ color: theme.palette.text.secondary }} data-testid="hunt-sigma-generate-reason">
          {reason}
        </Text>
      )}
      {xtmOneMissing && (canSetParameters ? (
        <Button variant="tertiary" size="small" component={Link} to={XTM_ONE_SETTINGS_PATH} data-testid="hunt-sigma-generate-settings">
          {t_i18n('Open the settings')}
        </Button>
      ) : (
        <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Ask your administrator')}</Text>
      ))}
      {inFlight && <Spinner size="sm" label={t_i18n('XTM One is writing the Sigma rule')} />}
      <Button
        variant="tertiary"
        size="small"
        startIcon={<AutoAwesomeOutlined fontSize="small" />}
        onClick={generate}
        disabled={disabled || unavailable || inFlight}
        data-testid="hunt-sigma-generate"
      >
        {t_i18n('Generate with AI')}
      </Button>
      {!isEnterpriseEdition && <EEChip feature={t_i18n('Generate with AI')} size="sm" style={{ marginInlineStart: 0 }} />}
    </div>
  );

  return (
    <>
      <Field
        component={HuntCodeEditorField}
        name="sigma_rule"
        label={label}
        language="yaml"
        placeholder={placeholder}
        minRows={minRows}
        maxRows={maxRows}
        disabled={disabled}
        helperText={helperText}
        labelAction={action}
        testId={testId}
      />
      {applied && (
        <div style={{ marginTop: theme.spacing(1) }} role="status">
          <Alert
            severity="info"
            title={t_i18n('Sigma rule written with XTM One')}
            description={[applied.rationale, nextStep?.sentence ?? t_i18n('Review it before saving.')].filter(Boolean).join(' ')}
            action={(
              <div style={{ display: 'flex', gap: theme.spacing(1) }}>
                <Button variant="secondary" size="small" onClick={undo} data-testid="hunt-sigma-generate-undo">
                  {t_i18n('Undo')}
                </Button>
                {nextStep?.action}
              </div>
            )}
            data-testid="hunt-sigma-generated"
          />
        </div>
      )}
      {error && (
        <div style={{ marginTop: theme.spacing(1) }} role="alert">
          <Alert severity="error" title={t_i18n('The Sigma rule could not be generated')} description={error} data-testid="hunt-sigma-generate-error" />
        </div>
      )}
      <HuntSigmaValidation sigmaRule={sigmaRule} />
    </>
  );
};

export default HuntSigmaRuleField;
