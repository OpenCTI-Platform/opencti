import React from 'react';
import { useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import ObservableTypesField from '../common/form/ObservableTypesField';
import { HuntHelp } from './HuntLearnMore';
import HuntFormSectionTitle from './HuntFormSectionTitle';
import { HUNT_DOCS, huntExtractsObservables, huntObservableTypeNames, huntRunProducesDescription } from './hunt-utils';
import useHuntConfiguration from './useHuntConfiguration';
import { HuntAIAction } from './HuntAIAssist';

/** The default observable types of the platform by their names, once loaded. */
export const useHuntDefaultObservableTypeNames = (): string | null => {
  const { t_i18n } = useFormatter();
  const { defaultExpectedObservables } = useHuntConfiguration();
  return defaultExpectedObservables.length > 0 ? huntObservableTypeNames(defaultExpectedObservables, t_i18n) : null;
};

/**
 * The "What a run produces" section of the hunt forms: what a run of the hunt type records, then the observable types
 * its hunt connectors extract from the hits, for the hunt types that extract them.
 */
const HuntRunProducesSection = ({ huntType }: { huntType: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { values } = useFormikContext<{ expected_observables?: string[] | null }>();
  const defaultTypes = useHuntDefaultObservableTypeNames();
  // The input keeps its placeholder next to the chips: the default types are only named while none is chosen
  const placeholder = defaultTypes && (values.expected_observables ?? []).length === 0
    ? t_i18n('Default types: {types}', { values: { types: defaultTypes } })
    : undefined;
  return (
    <>
      <HuntFormSectionTitle>{t_i18n('What a run produces')}</HuntFormSectionTitle>
      <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }} data-testid="hunt-run-produces">
        <HuntHelp text={t_i18n(huntRunProducesDescription(huntType))} href={HUNT_DOCS.produces} />
      </Text>
      {huntExtractsObservables(huntType) && (
        <ObservableTypesField
          name="expected_observables"
          label={t_i18n('Observables to extract from hits')}
          helperText={t_i18n('The values of these types found in the hits become observables, when the hunt connector supports them.')}
          placeholder={placeholder}
          multiple
          style={fieldSpacingContainerStyle}
          labelAction={<HuntAIAction request={{ kind: 'expected_observables' }} testId="hunt-observables-generate" />}
        />
      )}
    </>
  );
};

export default HuntRunProducesSection;
