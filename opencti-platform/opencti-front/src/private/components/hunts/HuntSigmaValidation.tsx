import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Chip, Spinner, Text } from '@filigran/design-system';
import { CheckCircleOutlined, ErrorOutlineOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery } from '../../../relay/environment';
import { huntUnresolvedTechniquesSentence } from './hunt-utils';
import { HuntSigmaValidationQuery$data } from './__generated__/HuntSigmaValidationQuery.graphql';

export const huntSigmaValidationQuery = graphql`
  query HuntSigmaValidationQuery($sigma_rule: String!) {
    huntSigmaValidate(sigma_rule: $sigma_rule) {
      valid
      errors
      title
      level
      logsource_product
      logsource_category
      logsource_service
      detection_fields
      attack_techniques
      unresolved_attack_techniques
    }
  }
`;

export type HuntSigmaValidationResult = HuntSigmaValidationQuery$data['huntSigmaValidate'];

export type HuntSigmaValidationStatus = 'idle' | 'validating' | 'done' | 'error';

export interface HuntSigmaValidationState {
  status: HuntSigmaValidationStatus;
  result: HuntSigmaValidationResult | null;
}

export const SIGMA_VALIDATION_DEBOUNCE_MS = 600;

/** Validates a Sigma rule on the platform, debounced; responses of outdated rules are ignored. */
export const useHuntSigmaValidation = (sigmaRule: string, delay = SIGMA_VALIDATION_DEBOUNCE_MS): HuntSigmaValidationState => {
  const [state, setState] = useState<HuntSigmaValidationState>({ status: 'idle', result: null });
  const requestCounter = useRef(0);
  useEffect(() => {
    requestCounter.current += 1;
    const requestId = requestCounter.current;
    if (sigmaRule.trim().length === 0) {
      setState({ status: 'idle', result: null });
      return undefined;
    }
    setState((current) => ({ status: 'validating', result: current.result }));
    const timer = setTimeout(() => {
      fetchQuery(huntSigmaValidationQuery, { sigma_rule: sigmaRule })
        .toPromise()
        .then((data) => {
          if (requestId === requestCounter.current) {
            const response = data as HuntSigmaValidationQuery$data | undefined;
            setState({ status: 'done', result: response?.huntSigmaValidate ?? null });
          }
        })
        .catch(() => {
          if (requestId === requestCounter.current) {
            setState({ status: 'error', result: null });
          }
        });
    }, delay);
    return () => clearTimeout(timer);
  }, [sigmaRule, delay]);
  return state;
};

const levelSeverity = (level?: string | null) => {
  switch ((level ?? '').toLowerCase()) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'neutral' as const;
  }
};

export const sigmaLevelLabel = (level?: string | null) => {
  switch ((level ?? '').toLowerCase()) {
    case 'informational': return 'Informational';
    case 'low': return 'Low';
    case 'medium': return 'Medium';
    case 'high': return 'High';
    case 'critical': return 'Critical';
    default: return 'Unknown';
  }
};

interface HuntSigmaValidationPanelProps {
  status: HuntSigmaValidationStatus;
  result: HuntSigmaValidationResult | null;
}

/** Outcome of the Sigma validation: errors, or the metadata the platform read from the rule. */
export const HuntSigmaValidationPanel = ({ status, result }: HuntSigmaValidationPanelProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const row = (label: string, content: React.ReactNode) => (
    <div style={{ display: 'flex', gap: theme.spacing(1), alignItems: 'center', flexWrap: 'wrap', marginTop: theme.spacing(0.5) }}>
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary, minWidth: 140 }}>{label}</Text>
      {content}
    </div>
  );

  let content: React.ReactNode;
  if (status === 'idle') {
    content = <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary }}>{t_i18n('Write a Sigma rule to validate it')}</Text>;
  } else if (status === 'error') {
    content = <Text variant="content-compact" style={{ color: theme.palette.error.main }}>{t_i18n('The Sigma rule could not be validated, try again later')}</Text>;
  } else if (status === 'validating' && !result) {
    content = <Spinner size="md" label={t_i18n('Validating the Sigma rule')} />;
  } else if (result && !result.valid) {
    content = (
      <>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), color: theme.palette.error.main }}>
          <ErrorOutlineOutlined fontSize="small" aria-hidden />
          <Text variant="content-compact-bold">{t_i18n('Invalid Sigma rule')}</Text>
          {status === 'validating' && <Spinner size="md" />}
        </div>
        <ul style={{ margin: `${theme.spacing(0.5)} 0 0 0`, paddingLeft: theme.spacing(3) }} data-testid="hunt-sigma-errors">
          {result.errors.map((error) => (
            <li key={error}><Text variant="content-compact">{error}</Text></li>
          ))}
        </ul>
      </>
    );
  } else if (result) {
    const logsource = [result.logsource_product, result.logsource_category, result.logsource_service].filter((part) => !!part).join(' / ');
    content = (
      <>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), color: theme.palette.success.main }}>
          <CheckCircleOutlined fontSize="small" aria-hidden />
          <Text variant="content-compact-bold">{t_i18n('Valid Sigma rule')}</Text>
          {status === 'validating' && <Spinner size="md" />}
        </div>
        {row(t_i18n('Title'), <Text variant="content-compact">{result.title ?? '-'}</Text>)}
        {row(t_i18n('Level'), result.level ? <Chip label={t_i18n(sigmaLevelLabel(result.level))} severity={levelSeverity(result.level)} /> : <Text variant="content-compact">-</Text>)}
        {row(t_i18n('Log source'), <Text variant="content-compact">{logsource.length > 0 ? logsource : '-'}</Text>)}
        {row(
          t_i18n('Detection fields'),
          result.detection_fields.length > 0
            ? result.detection_fields.map((field) => <Chip key={field} label={field} />)
            : <Text variant="content-compact">-</Text>,
        )}
        {row(
          t_i18n('ATT&CK techniques'),
          result.attack_techniques.length > 0
            ? result.attack_techniques.map((technique) => <Chip key={technique} label={technique} entity="techniques" />)
            : <Text variant="content-compact">-</Text>,
        )}
        {result.unresolved_attack_techniques.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: theme.spacing(1), marginTop: theme.spacing(1) }} data-testid="hunt-sigma-unresolved-techniques">
            <WarningAmberOutlined fontSize="small" style={{ color: theme.palette.warn.main }} aria-hidden />
            <Text variant="content-compact">{huntUnresolvedTechniquesSentence(result.unresolved_attack_techniques, t_i18n)}</Text>
          </div>
        )}
      </>
    );
  }

  return (
    <div role="status" aria-live="polite" data-testid="hunt-sigma-validation" style={{ marginTop: theme.spacing(1) }}>
      {content}
    </div>
  );
};

/** Live validation of a Sigma rule, displayed under the rule editor. */
const HuntSigmaValidation = ({ sigmaRule }: { sigmaRule: string }) => {
  const { status, result } = useHuntSigmaValidation(sigmaRule);
  return <HuntSigmaValidationPanel status={status} result={result} />;
};

export default HuntSigmaValidation;
