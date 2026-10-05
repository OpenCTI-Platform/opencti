import React, { InputHTMLAttributes, Suspense, useId, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined, FileUploadOutlined } from '@mui/icons-material';
import { Alert, Button, Checkbox, Paper, Radio, RadioGroup, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../common/VisuallyHiddenInput';
import HuntPlanDialog from './HuntPlanDialog';
import { huntPackImportMutation, notifyHuntPackImport } from './HuntPack';
import { useHuntPlanDisabledReason } from './HuntQuickStartMenu';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { parseIocText } from './hunt-ioc-utils';
import {
  buildHuntSummary,
  countHuntPlatforms,
  derivedRuleValues,
  formatDerivedValueTypes,
  hasHuntLogic,
  HUNT_DEFAULT_ESCALATION_THRESHOLD,
  HUNT_DEFAULT_TIME_WINDOW_HOURS,
  type HuntDerived,
  type HuntDerivedSource,
  type HuntFormValues,
  huntQueryLanguageLabel,
  huntTechniqueName,
  normalizeNativeQueries,
  selectedDerivedElements,
  selectedDerivedRule,
} from './hunt-utils';
import { HuntFromEntityConnectorsQuery } from './__generated__/HuntFromEntityConnectorsQuery.graphql';
import { HuntPackImportMutation } from './__generated__/HuntPackImportMutation.graphql';

export const huntFromEntityDerivedQuery = graphql`
  query HuntFromEntityDerivedQuery($entityId: ID!) {
    huntDerivedContent(entityId: $entityId) {
      entity { id entity_type name relation }
      suggested_type
      sources { id entity_type name relation }
      targets { id entity_type name relation }
      elements { id entity_type name value_types source_ids }
      elements_truncated
      unsupported_count
      techniques { id entity_type name x_mitre_id }
      rules { id entity_type name pattern_type pattern technique_ids }
    }
  }
`;

const huntFromEntityConnectorsQuery = graphql`
  query HuntFromEntityConnectorsQuery {
    huntConnectors(onlyAlive: true) {
      id
      platform
      supports_indicators
      securityPlatform {
        id
      }
    }
  }
`;

const toNumber = (value: number | string, fallback: number) => {
  const numeric = Number(value);
  return value === '' || !Number.isFinite(numeric) ? fallback : numeric;
};

// region summary
const SummaryContent = ({ derived }: { derived: HuntDerived }) => {
  const { t_i18n } = useFormatter();
  const { values } = useFormikContext<HuntFormValues>();
  const { huntConnectors } = useLazyLoadQuery<HuntFromEntityConnectorsQuery>(huntFromEntityConnectorsQuery, {}, { fetchPolicy: 'store-and-network' });
  const rule = selectedDerivedRule(derived, values);
  const sentences = buildHuntSummary({
    name: derived.entity.name,
    huntType: values.hunt_type,
    scopePlatforms: values.scopePlatforms,
    availablePlatforms: countHuntPlatforms(huntConnectors, values.hunt_type),
    indicatorsCount: selectedDerivedElements(derived, values).length + parseIocText(values.ioc_values_text).values.length,
    ruleName: rule?.name ?? null,
    hasLogic: hasHuntLogic({ hunt_type: values.hunt_type, sigma_rule: values.sigma_rule, native_queries: normalizeNativeQueries(values.native_queries) }),
    timeWindowHours: toNumber(values.time_window_hours, HUNT_DEFAULT_TIME_WINDOW_HOURS),
    escalationThreshold: toNumber(values.escalation_threshold, HUNT_DEFAULT_ESCALATION_THRESHOLD),
  }, t_i18n);
  return (
    <Alert
      severity="info"
      title={sentences[0]}
      description={sentences.slice(1).join(' ')}
      data-testid="hunt-from-entity-summary"
    />
  );
};

/** What the hunt does, in plain language, updated as the type, the scope, the window and the threshold change. */
export const HuntFromEntitySummary = ({ derived, style }: { derived: HuntDerived; style?: React.CSSProperties }) => (
  <div style={style} aria-live="polite">
    <Suspense fallback={null}>
      <SummaryContent derived={derived} />
    </Suspense>
  </div>
);
// endregion

// region derived content
const SourceDescription = ({ source, entityName, count }: { source: HuntDerivedSource; entityName: string; count: number }) => {
  const { t_i18n } = useFormatter();
  const indicators = t_i18n('{count, plural, =0 {no indicator} one {# indicator} other {# indicators}}', { values: { count } });
  const type = t_i18n(`entity_${source.entity_type}`);
  if (source.relation === 'uses') return <>{t_i18n('{type} used by {name}, {indicators}', { values: { type, name: entityName, indicators } })}</>;
  if (source.relation === 'attributed') return <>{t_i18n('{type} attributed to {name}, {indicators}', { values: { type, name: entityName, indicators } })}</>;
  return <>{t_i18n('{type}, {indicators}', { values: { type, indicators } })}</>;
};

const PackImportButton = () => {
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [commitImport, importing] = useApiMutation<HuntPackImportMutation>(huntPackImportMutation);
  const handleImport: InputHTMLAttributes<HTMLInputElement>['onChange'] = (event) => {
    const file = event.target?.files?.[0];
    if (file) {
      commitImport({
        variables: { file },
        onCompleted: (data, errors) => {
          if (!notifyPayloadErrors(errors)) {
            notifyHuntPackImport(t_i18n, data.huntPackImport);
          }
        },
      });
    }
    if (inputRef.current) inputRef.current.value = '';
  };
  return (
    <>
      <VisuallyHiddenInput ref={inputRef} type="file" accept="application/json,.json" onChange={handleImport} data-testid="hunt-derived-pack-input" />
      <Button priority="secondary" size="sm" startIcon={<FileUploadOutlined fontSize="small" />} disabled={importing} onClick={() => inputRef.current?.click()} data-testid="hunt-derived-import-pack">
        {t_i18n('Import a hunt pack')}
      </Button>
    </>
  );
};

const EmptyDerivation = ({ derived }: { derived: HuntDerived }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const planDisabledReason = useHuntPlanDisabledReason();
  const [planOpen, setPlanOpen] = useState(false);
  const planButton = (
    <Button
      priority="secondary"
      size="sm"
      startIcon={<AutoAwesomeOutlined fontSize="small" />}
      disabled={!!planDisabledReason}
      aria-description={planDisabledReason ?? undefined}
      onClick={() => setPlanOpen(true)}
      data-testid="hunt-derived-plan"
    >
      {t_i18n('Plan the hunt with AI')}
    </Button>
  );
  return (
    <div data-testid="hunt-derived-empty">
      <Text variant="content-compact" style={{ display: 'block' }}>
        {t_i18n('The platform holds no indicator or detection rule for {name} yet: plan the hunt with AI, import a hunt pack, or write its logic below.', { values: { name: derived.entity.name } })}
      </Text>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(1), marginTop: theme.spacing(1) }}>
        {planDisabledReason ? (
          <Tooltip>
            <TooltipTrigger asChild><span>{planButton}</span></TooltipTrigger>
            <TooltipContent>{planDisabledReason}</TooltipContent>
          </Tooltip>
        ) : planButton}
        <PackImportButton />
      </div>
      <HuntPlanDialog open={planOpen} onClose={() => setPlanOpen(false)} entityIds={[derived.entity.id]} />
    </div>
  );
};

const RULES_LIST_MAX_HEIGHT = 280;

/**
 * What "Hunt this" found for the entity: the indicators an indicator hunt looks up, per source, with their count and
 * types; the detection rules of its techniques, to pick from; or, when the platform holds neither, the other ways to
 * start the hunt.
 */
export const HuntDerivedPanel = ({ derived, style }: { derived: HuntDerived; style?: React.CSSProperties }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { values, setValues } = useFormikContext<HuntFormValues>();
  const rulesLabelId = useId();
  const name = derived.entity.name;
  const selectedElements = selectedDerivedElements(derived, values);
  const selectedRule = selectedDerivedRule(derived, values);
  const techniquesById = new Map(derived.techniques.map((technique) => [technique.id, technique]));
  const coveredTechniques = new Set(derived.rules.flatMap((rule) => rule.technique_ids));
  const hasElements = derived.elements.length > 0;
  const hasRules = derived.rules.length > 0;
  const isIndicatorHunt = values.hunt_type === 'indicators';
  const isInfrastructureHunt = values.hunt_type === 'infrastructure';

  const toggleSource = (source: HuntDerivedSource, checked: boolean) => {
    const others = values.iocEntities.filter((option) => option.value !== source.id);
    const iocEntities = checked ? [...others, { value: source.id, label: source.name, type: source.entity_type }] : others;
    setValues({ ...values, iocEntities });
  };
  const huntIndicators = () => {
    const iocEntities = derived.sources.map((source) => ({ value: source.id, label: source.name, type: source.entity_type }));
    setValues({ ...values, hunt_type: 'indicators', iocEntities: derived.sources.length > 0 ? iocEntities : values.iocEntities });
  };
  const pickRule = (ruleId: string) => {
    const rule = derived.rules.find(({ id }) => id === ruleId);
    if (rule) setValues({ ...values, ...derivedRuleValues(rule, derived) });
  };

  return (
    <Paper padding={16} style={style} data-testid="hunt-derived-panel">
      <Text variant="title-xs" as="h3" style={{ margin: 0 }}>
        {t_i18n('What the platform found for {name}', { values: { name } })}
      </Text>
      {isInfrastructureHunt && (
        <Text variant="content-compact" style={{ display: 'block', marginTop: theme.spacing(1) }} data-testid="hunt-derived-infrastructure">
          {t_i18n('An internet infrastructure hunt uses neither these indicators nor these rules: write its fingerprint query in the Logic section.')}
        </Text>
      )}
      {!hasElements && !hasRules && (
        <div style={{ marginTop: theme.spacing(1) }}>
          <EmptyDerivation derived={derived} />
        </div>
      )}
      {hasElements && (
        <section style={{ marginTop: theme.spacing(1.5) }} data-testid="hunt-derived-indicators">
          <Text variant="content-compact-medium" style={{ display: 'block' }}>
            {isIndicatorHunt
              ? t_i18n('{count, plural, =0 {No indicator selected} one {# indicator to look up} other {# indicators to look up}}', { values: { count: selectedElements.length } })
              : t_i18n('{count, plural, one {# indicator found} other {# indicators found}}', { values: { count: derived.elements.length } })}
            {(isIndicatorHunt ? selectedElements : derived.elements).length > 0 && `: ${formatDerivedValueTypes(isIndicatorHunt ? selectedElements : derived.elements, t_i18n)}`}
          </Text>
          {isIndicatorHunt && derived.sources.length > 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1), marginTop: theme.spacing(1) }}>
              {derived.sources.map((source) => (
                <Checkbox
                  key={source.id}
                  checked={values.iocEntities.some((option) => option.value === source.id)}
                  onCheckedChange={(checked) => toggleSource(source, checked === true)}
                  label={source.name}
                  description={<SourceDescription source={source} entityName={name} count={derived.elements.filter((element) => element.source_ids.includes(source.id)).length} />}
                  data-testid={`hunt-derived-source-${source.id}`}
                />
              ))}
            </div>
          )}
          {derived.elements_truncated && (
            <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
              {t_i18n('More values than a run looks up: the first ones are looked up at each run.')}
            </Text>
          )}
          {!isIndicatorHunt && (
            <div style={{ marginTop: theme.spacing(1) }}>
              <Button priority="secondary" size="sm" onClick={huntIndicators} data-testid="hunt-derived-use-indicators">
                {t_i18n('Hunt these indicators')}
              </Button>
            </div>
          )}
        </section>
      )}
      {hasRules && !isInfrastructureHunt && (
        <section style={{ marginTop: theme.spacing(2) }} data-testid="hunt-derived-rules">
          <Text variant="content-compact-medium" id={rulesLabelId} style={{ display: 'block' }}>
            {derived.techniques.length > 0
              ? t_i18n('{count, plural, one {# detection rule} other {# detection rules}} covering {covered} of the {techniques, plural, one {# technique} other {# techniques}} of {name}', {
                  values: { count: derived.rules.length, covered: coveredTechniques.size, techniques: derived.techniques.length, name },
                })
              : t_i18n('{count, plural, one {# detection rule} other {# detection rules}} of {name}', { values: { count: derived.rules.length, name } })}
          </Text>
          <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary }}>
            {t_i18n('Pick the rule the hunt runs on your telemetry.')}
          </Text>
          <div style={{ maxHeight: RULES_LIST_MAX_HEIGHT, overflowY: 'auto', marginTop: theme.spacing(1) }}>
            <RadioGroup aria-labelledby={rulesLabelId} value={selectedRule?.id ?? ''} onValueChange={pickRule}>
              {derived.rules.map((rule) => {
                const techniques = rule.technique_ids.map((id) => techniquesById.get(id)).filter((technique) => !!technique).map((technique) => huntTechniqueName(technique));
                const language = rule.pattern_type === 'sigma' ? 'Sigma' : huntQueryLanguageLabel(rule.pattern_type, t_i18n);
                return (
                  <Radio
                    key={rule.id}
                    value={rule.id}
                    label={rule.name}
                    description={techniques.length > 0
                      ? t_i18n('{language} rule, covers {techniques}', { values: { language, techniques: techniques.join(', ') } })
                      : t_i18n('{language} rule', { values: { language } })}
                    data-testid={`hunt-derived-rule-${rule.id}`}
                  />
                );
              })}
            </RadioGroup>
          </div>
        </section>
      )}
      {!hasRules && hasElements && derived.techniques.length > 0 && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1.5), color: theme.palette.text.secondary }} data-testid="hunt-derived-no-rule">
          {t_i18n('No detection rule indicates the {count, plural, one {# technique} other {# techniques}} of {name}.', { values: { count: derived.techniques.length, name } })}
        </Text>
      )}
      {derived.unsupported_count > 0 && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
          {t_i18n('{count, plural, one {# indicator is} other {# indicators are}} in a pattern language a hunt cannot run (YARA, Snort, Suricata...).', { values: { count: derived.unsupported_count } })}
        </Text>
      )}
    </Paper>
  );
};
// endregion
