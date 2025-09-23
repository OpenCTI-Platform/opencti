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

import { Field, useFormikContext } from 'formik';
import React from 'react';
import MenuItem from '@mui/material/MenuItem';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { PirCreationFormData } from '@components/pir/pir_form/pir-form-utils';
import Alert from '@mui/material/Alert';
import { AlertTitle } from '@mui/material';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import { PirCreationFormGeneralSettingsRedisStreamQuery } from './__generated__/PirCreationFormGeneralSettingsRedisStreamQuery.graphql';
import { daysAgo, minutesBetweenDates } from '../../../../utils/Time';

export const redisStreamQuery = graphql`
  query PirCreationFormGeneralSettingsRedisStreamQuery {
    redisStreamInfo {
      firstEventDate
    }
  }
`;

interface PirCreationFormGeneralSettingsProps {
  redisQueryRef: PreloadedQuery<PirCreationFormGeneralSettingsRedisStreamQuery>;
}

const PirCreationFormGeneralSettings = ({ redisQueryRef }: PirCreationFormGeneralSettingsProps) => {
  const { t_i18n, fld } = useFormatter();
  const dataRedis = usePreloadedQuery(redisStreamQuery, redisQueryRef);
  const firstEventDate = dataRedis.redisStreamInfo?.firstEventDate;

  const { values } = useFormikContext<PirCreationFormData>();
  const { pir_rescan_days } = values;

  const dateOfRescanStart = daysAgo(pir_rescan_days);
  const diffBetweenStreamStartAndRescan = minutesBetweenDates(firstEventDate, dateOfRescanStart);
  const showRescanAlert = pir_rescan_days > 0 && diffBetweenStreamStartAndRescan < 0; // true if first stream event date is more recent than rescan start date

  return (
    <>
      <Field
        name="name"
        required
        component={TextField}
        variant="standard"
        label={t_i18n('Name')}
        style={fieldSpacingContainerStyle}
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t_i18n('Description')}
        rows="4"
        style={fieldSpacingContainerStyle}
      />
      <Field
        component={SelectField}
        required
        variant="standard"
        name="pir_rescan_days"
        label={t_i18n('Rescan period (days)')}
        fullWidth={true}
        containerstyle={{ marginTop: 20, width: '100%' }}
        helpertext={t_i18n('How far back to rescan at creation. If the PIR engine has less history than this period, only the history period will be taken')}
      >
        <MenuItem value={0}>{t_i18n('No rescan')}</MenuItem>
        <MenuItem value={1}>{t_i18n('1 day')}</MenuItem>
        <MenuItem value={30}>{t_i18n('1 month')}</MenuItem>
        <MenuItem value={182}>{t_i18n('6 months')}</MenuItem>
      </Field>
      {showRescanAlert
        && <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
          <AlertTitle>{t_i18n('Rescan begins before stream first event date')}</AlertTitle>
          {t_i18n(
            'Events before stream first event date ({firstEventDate}) won\'t be taken into account.',
            { values: { firstEventDate: fld(firstEventDate) } },
          )}
        </Alert>
      }
    </>
  );
};

export default PirCreationFormGeneralSettings;
