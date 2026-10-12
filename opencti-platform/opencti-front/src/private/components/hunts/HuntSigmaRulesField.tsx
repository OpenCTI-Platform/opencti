import React from 'react';
import { FieldArray, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { IconButton, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import HuntSigmaRuleField from './HuntSigmaRuleField';
import useHuntConfiguration from './useHuntConfiguration';

interface HuntSigmaRulesFieldProps {
  label: string;
  helperText: string;
  placeholder: string;
  minRows?: number;
  maxRows?: number;
  disabled?: boolean;
  testId: string;
}

interface SigmaRulesValues {
  sigma_rule: string;
  more_sigma_rules: string[];
}

/**
 * The Sigma rules of a hunt: the first one, which "Generate with AI" writes, and the others, each translated and run on
 * its own with its own results.
 */
const HuntSigmaRulesField = ({ label, helperText, placeholder, minRows = 10, maxRows, disabled = false, testId }: HuntSigmaRulesFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { maxSigmaRules } = useHuntConfiguration();
  const { values } = useFormikContext<SigmaRulesValues>();
  const more = values.more_sigma_rules ?? [];
  const count = 1 + more.length;
  return (
    <FieldArray name="more_sigma_rules">
      {({ push, remove }) => (
        <div data-testid={`${testId}-list`}>
          <HuntSigmaRuleField
            label={more.length > 0 ? `${label} 1` : label}
            helperText={helperText}
            placeholder={placeholder}
            minRows={minRows}
            maxRows={maxRows}
            disabled={disabled}
            testId={testId}
          />
          {more.map((_, index) => (
            <div key={index} style={{ marginTop: theme.spacing(2) }}>
              <HuntSigmaRuleField
                name={`more_sigma_rules.${index}`}
                label={`${label} ${index + 2}`}
                helperText={t_i18n('Translated and run on its own, with its own results')}
                placeholder={placeholder}
                minRows={Math.min(minRows, 8)}
                maxRows={maxRows}
                disabled={disabled}
                aiAssist={false}
                action={(
                  <IconButton
                    priority="tertiary"
                    variant="destructive"
                    size="sm"
                    aria-label={t_i18n('Remove this Sigma rule')}
                    icon={<DeleteOutlined fontSize="small" aria-hidden />}
                    disabled={disabled}
                    onClick={() => remove(index)}
                    data-testid={`${testId}-remove-${index + 2}`}
                  />
                )}
                testId={`${testId}-${index + 2}`}
              />
            </div>
          ))}
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginTop: theme.spacing(1) }}>
            <Button
              variant="tertiary"
              size="small"
              startIcon={<AddOutlined fontSize="small" />}
              onClick={() => push('')}
              disabled={disabled || count >= maxSigmaRules}
              data-testid={`${testId}-add`}
            >
              {t_i18n('Add a Sigma rule')}
            </Button>
            <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
              {t_i18n('Up to {max} Sigma rules, each translated and run on its own', { values: { max: maxSigmaRules } })}
            </Text>
          </div>
        </div>
      )}
    </FieldArray>
  );
};

export default HuntSigmaRulesField;
