import React, { useId } from 'react';
import { useField } from 'formik';
import { useTheme } from '@mui/styles';
import { Radio, RadioGroup, Text } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { HuntHelp } from './HuntLearnMore';
import { HUNT_DOCS, HUNT_TYPES, huntTypeDescription, huntTypeLabel, type HuntTypeValue } from './hunt-utils';

interface HuntTypeFieldProps {
  name?: string;
  style?: React.CSSProperties;
  /** The action of the form header, at the end of the label row (for instance "Plan with AI") */
  action?: React.ReactNode;
}

/** The hunt types, each with what it needs as input and where it runs. */
const HuntTypeField = ({ name = 'hunt_type', style, action }: HuntTypeFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [field, , helpers] = useField<HuntTypeValue>(name);
  const labelId = useId();
  return (
    <div style={style} data-testid="hunt-type-field">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1), minHeight: 28, marginBottom: theme.spacing(1) }}>
        <Text variant="content-compact-medium" id={labelId}>
          {t_i18n('Hunt type')}
        </Text>
        {action}
      </div>
      <RadioGroup
        aria-labelledby={labelId}
        value={field.value}
        onValueChange={(value) => helpers.setValue(value as HuntTypeValue)}
      >
        {HUNT_TYPES.map((huntType) => (
          <Radio
            key={huntType}
            value={huntType}
            label={t_i18n(huntTypeLabel(huntType))}
            description={t_i18n(huntTypeDescription(huntType))}
            data-testid={`hunt-type-${huntType}`}
          />
        ))}
      </RadioGroup>
      <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
        <HuntHelp text={t_i18n('Pick the type from what you have: indicators, a detection rule or an internet fingerprint.')} href={HUNT_DOCS.types} />
      </Text>
    </div>
  );
};

export default HuntTypeField;
