import React from 'react';
import LocationField from '@components/common/form/LocationField';
import SectorField from '@components/common/form/SectorField';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';

const PirCreationFormCriteria = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <LocationField
        name="locations"
        label={t_i18n('Targeted locations')}
      />
      <SectorField
        name="sectors"
        label={t_i18n('Targeted industries')}
        containerStyle={fieldSpacingContainerStyle}
      />
      <div style={{ overflow: 'hidden' }}>
        <ConfidenceField
          name="confidence"
          label={t_i18n('Minimum confidence of the relationship')}
          containerStyle={fieldSpacingContainerStyle}
        />
      </div>
    </>
  );
};

export default PirCreationFormCriteria;
