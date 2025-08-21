/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import LocationField from '@components/common/form/LocationField';
import SectorField from '@components/common/form/SectorField';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const PirCreationFormCriteria = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <LocationField
        name="locations"
        label={t_i18n('Targeted locations')}
        helperText={t_i18n('Pir targeted locations...')}
      />
      <SectorField
        name="sectors"
        label={t_i18n('Targeted industries')}
        containerStyle={fieldSpacingContainerStyle}
        helperText={t_i18n('Pir targeted sectors...')}
      />
      <div style={{ overflow: 'hidden' }}>
        <ConfidenceField
          name="confidence"
          label={t_i18n('Minimum confidence of the relationship')}
          containerStyle={fieldSpacingContainerStyle}
          helperText={t_i18n('Pir confidence...')}
        />
      </div>
    </>
  );
};

export default PirCreationFormCriteria;
