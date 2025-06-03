import { Field, useFormikContext } from 'formik';
import React from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import MenuItem from '@mui/material/MenuItem';
import { Select } from '@mui/material';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { PirCreationFormData } from '@components/pir/pir-form-utils';
import MarkdownField from '../../../components/fields/MarkdownField';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import TextField from '../../../components/TextField';

const PirCreationFormGeneralSettings = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue, values } = useFormikContext<PirCreationFormData>();

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
      <ObjectMarkingField
        name="markings"
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
      />
      <div
        style={{ marginTop: 20, display: 'flex', gap: 1, alignItems: 'center' }}
      >
        {t_i18n('Rescan period*')}
        <Tooltip title={t_i18n('TODO')} style={{ marginLeft: 5 }}>
          <InformationOutline fontSize="small" color="primary" />
        </Tooltip>
      </div>
      <Select
        style={{ marginTop: 5 }}
        size="small"
        name="pir_rescan_days"
        variant="outlined"
        value={values.pir_rescan_days}
        onChange={(event) => setFieldValue('pir_rescan_days', event.target.value)}
      >
        <MenuItem value={0}>{t_i18n('No rescan')}</MenuItem>
        <MenuItem value={1}>{t_i18n('1 day')}</MenuItem>
        <MenuItem value={30}>{t_i18n('1 month')}</MenuItem>
        <MenuItem value={182}>{t_i18n('6 months')}</MenuItem>
      </Select>
    </>
  );
};

export default PirCreationFormGeneralSettings;
