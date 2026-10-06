import React, { useId } from 'react';
import { Field } from 'formik';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import TextareaField from '../../../components/TextareaField';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { HuntHelp } from './HuntLearnMore';
import { HuntAIAction } from './HuntAIAssist';
import { HUNT_DOCS } from './hunt-utils';

/** The benign patterns of a hunt, one per line, with the "Generate with AI" of the form in the label row. */
const HuntBenignPatternsField = ({ style }: { style?: React.CSSProperties }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const id = useId();
  return (
    <div style={style} data-testid="hunt-benign-patterns">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1), minHeight: 28, marginBottom: theme.spacing(0.5) }}>
        <Text as="label" htmlFor={id} variant="content-compact" style={{ color: theme.palette.text.secondary }}>
          {t_i18n('Benign patterns (one per line)')}
        </Text>
        <HuntAIAction request={{ kind: 'benign_patterns' }} testId="hunt-benign-generate" />
      </div>
      <Field
        component={TextareaField}
        name="benign_patterns"
        id={id}
        rows={3}
        helperText={<HuntHelp text={t_i18n('Known legitimate activity the triage must not escalate, for example a backup service account')} href={HUNT_DOCS.runs} />}
      />
    </div>
  );
};

export default HuntBenignPatternsField;
