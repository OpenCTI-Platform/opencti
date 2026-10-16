import React from 'react';
import { Field, FieldArray, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { IconButton, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import TextField from '../../../components/TextField';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { HuntCodeEditorField } from './HuntCodeEditor';
import { HuntAIAction } from './HuntAIAssist';
import {
  HUNT_DOCS,
  HUNT_FIRST_RULE,
  HUNT_INFRASTRUCTURE_PLATFORMS,
  HUNT_LANGUAGE_FINGERPRINT,
  HUNT_PLATFORM_DEFAULT_LANGUAGE,
  HUNT_PLATFORMS,
  HUNT_QUERY_LANGUAGES,
  huntPlatformLabel,
  huntQueryLanguageLabel,
  type HuntNativeQueryFormValue,
} from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';

interface HuntNativeQueriesFieldProps {
  name?: string;
  /** The field label, left out where a card title already names the field */
  label?: string;
  disabled?: boolean;
  /** The saved Sigma rules a native query can replace, offered from two rules */
  ruleOptions?: ReadonlyArray<{ value: string; label: string }>;
  /** The fingerprint documents of an infrastructure hunt, written for the internet scanning services */
  infrastructure?: boolean;
}

interface NativeQueriesValues {
  [key: string]: unknown;
}

const emptyRow = (): HuntNativeQueryFormValue => ({ platform: '', language: '', query: '', pipeline: '' });

/**
 * Per-platform native query overrides: when a row matches the platform of a hunt connector,
 * the connector executes this query verbatim instead of translating the Sigma rule.
 */
const HuntNativeQueriesField = ({ name = 'native_queries', label, disabled = false, ruleOptions = [], infrastructure = false }: HuntNativeQueriesFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<NativeQueriesValues>();
  const rows = (values[name] ?? []) as HuntNativeQueryFormValue[];
  const platforms: ReadonlyArray<string> = infrastructure ? HUNT_INFRASTRUCTURE_PLATFORMS : HUNT_PLATFORMS;
  const languages: ReadonlyArray<string> = infrastructure ? [HUNT_LANGUAGE_FINGERPRINT] : HUNT_QUERY_LANGUAGES;
  const helper = (
    <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary }}>
      {infrastructure
        ? t_i18n('Each internet scanning service runs the fingerprint document written for it, or else the first one.')
        : t_i18n('Native queries override the Sigma translation on their platform.')}
    </Text>
  );

  return (
    <FieldArray name={name}>
      {({ push, remove }) => (
        <div data-testid="hunt-native-queries">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1), minHeight: 28 }}>
            {label ? <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{label}</Text> : helper}
            <Button
              variant="tertiary"
              size="small"
              startIcon={<AddOutlined fontSize="small" />}
              onClick={() => push(emptyRow())}
              disabled={disabled}
              data-testid="hunt-native-query-add"
            >
              {infrastructure ? t_i18n('Add a fingerprint document') : t_i18n('Add a native query')}
            </Button>
          </div>
          {label && helper}
          {rows.map((row, index) => (
            <div
              key={index}
              style={{
                marginTop: theme.spacing(2),
                padding: theme.spacing(2),
                border: `1px solid ${theme.palette.divider}`,
                borderRadius: theme.borderRadius,
              }}
            >
              <div style={{ display: 'flex', gap: theme.spacing(2), alignItems: 'flex-start' }}>
                <Field
                  component={SelectFieldFds}
                  name={`${name}.${index}.platform`}
                  label={t_i18n('Platform')}
                  required
                  disabled={disabled}
                  fullWidth
                  containerstyle={{ flex: 1 }}
                  helpertext={infrastructure
                    ? <HuntHelp text={t_i18n('The internet scanning service this document is written for')} href={`${HUNT_DOCS.connectors}#internet-scanning-services`} />
                    : <HuntHelp text={t_i18n('Its hunt connector runs this query instead of translating the Sigma rule')} href={HUNT_DOCS.createHunt} />}
                  onChange={(_: string, platform: string) => {
                    if (!row.language && HUNT_PLATFORM_DEFAULT_LANGUAGE[platform]) {
                      setFieldValue(`${name}.${index}.language`, HUNT_PLATFORM_DEFAULT_LANGUAGE[platform]);
                    }
                  }}
                >
                  {platforms.map((platform) => (
                    <SelectItem key={platform} value={platform}>{huntPlatformLabel(platform, t_i18n)}</SelectItem>
                  ))}
                </Field>
                <Field
                  component={SelectFieldFds}
                  name={`${name}.${index}.language`}
                  label={t_i18n('Query language')}
                  required
                  disabled={disabled}
                  fullWidth
                  containerstyle={{ flex: 1 }}
                  helpertext={infrastructure
                    ? t_i18n('Internet fingerprints, the same for every service')
                    : t_i18n('The language of the query, SPL for Splunk or KQL for Microsoft Sentinel')}
                >
                  {languages.map((language) => (
                    <SelectItem key={language} value={language}>{huntQueryLanguageLabel(language, t_i18n)}</SelectItem>
                  ))}
                </Field>
                <div style={{ paddingTop: 22 }}>
                  <IconButton
                    priority="tertiary"
                    variant="destructive"
                    aria-label={infrastructure ? t_i18n('Remove this fingerprint document') : t_i18n('Remove this native query')}
                    icon={<DeleteOutlined fontSize="small" aria-hidden />}
                    disabled={disabled}
                    onClick={() => remove(index)}
                  />
                </div>
              </div>
              {ruleOptions.length > 1 && (
                <div style={{ marginTop: theme.spacing(2) }}>
                  <Field
                    component={SelectFieldFds}
                    name={`${name}.${index}.rule_key`}
                    label={t_i18n('Replaces the Sigma rule')}
                    disabled={disabled}
                    fullWidth
                    helpertext={t_i18n('On its platform, this query runs instead of the translation of this rule; the other rules are still translated')}
                  >
                    {ruleOptions.map((option) => (
                      <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                    ))}
                    {row.rule_key && row.rule_key !== HUNT_FIRST_RULE && !ruleOptions.some((option) => option.value === row.rule_key) && (
                      <SelectItem value={row.rule_key}>{t_i18n('A rule the hunt no longer holds')}</SelectItem>
                    )}
                  </Field>
                </div>
              )}
              <div style={{ marginTop: theme.spacing(2) }}>
                <Field
                  component={HuntCodeEditorField}
                  name={`${name}.${index}.query`}
                  label={t_i18n('Query')}
                  language={row.language}
                  required
                  disabled={disabled}
                  minRows={4}
                  maxRows={16}
                  helperText={infrastructure
                    ? t_i18n('The fingerprints to look for and, optionally, a raw query per service, in YAML or JSON')
                    : t_i18n('Run as written within the time window of the run, for example index=edr CommandLine="* -enc *"')}
                  labelAction={row.platform && row.language ? (
                    <HuntAIAction request={{ kind: 'native_queries', nativeQueryIndex: index }} disabled={disabled} testId={`hunt-native-query-${index}-generate`} />
                  ) : undefined}
                  testId={`hunt-native-query-${index}`}
                />
              </div>
              {!infrastructure && (
                <div style={{ marginTop: theme.spacing(2) }}>
                  <Field
                    component={TextField}
                    variant="outlined"
                    name={`${name}.${index}.pipeline`}
                    label={t_i18n('pySigma pipeline (optional)')}
                    helperText={t_i18n('With an empty query, the pipeline the Sigma rule is translated with, for example splunk_windows. Left empty, the default of the connector.')}
                    disabled={disabled}
                    fullWidth
                  />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </FieldArray>
  );
};

export default HuntNativeQueriesField;
