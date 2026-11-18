import { Field } from 'formik';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import SelectFieldFds, { SelectItem } from '../../../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../../../components/i18n';
import type { Theme } from '../../../../../../components/Theme';

interface CsvMapperDefaultMarkingProps {
  name: string;
}

const CsvMapperDefaultMarking = ({ name }: CsvMapperDefaultMarkingProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginTop: theme.spacing(1.25) }}>
      <Field
        component={SelectFieldFds}
        name={name}
        containerstyle={{ flex: 1 }}
        fullWidth
        displayEmpty
      >
        <SelectItem value="user-choice">
          {t_i18n('Let the user choose marking definitions')}
        </SelectItem>
        <SelectItem value="user-default">
          {t_i18n('Use default marking definitions of the user')}
        </SelectItem>
      </Field>
      <Tooltip title={t_i18n("Option 'Let the user choose marking definitions'...")}>
        <InformationOutline
          fontSize="small"
          color="primary"
          style={{ cursor: 'default' }}
        />
      </Tooltip>
    </div>
  );
};

export default CsvMapperDefaultMarking;
