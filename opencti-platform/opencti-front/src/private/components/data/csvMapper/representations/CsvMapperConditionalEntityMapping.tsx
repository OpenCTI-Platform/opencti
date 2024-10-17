import React, { FunctionComponent } from 'react';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { Field } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';

// eslint-disable-next-line @typescript-eslint/no-empty-interface
interface CsvMapperConditionalEntityMappingProps {
  options: string
}

const CsvMapperConditionalEntityMapping: FunctionComponent<CsvMapperConditionalEntityMappingProps> = ({
  options,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <div style={{
      width: '100%',
      display: 'inline-grid',
      gridTemplateColumns: '2fr 2fr 2fr 50px',
      // display: 'flex',
      // justifyContent: 'center',
      alignItems: 'center',
      margin: '20px 0px 40px',
      gap: '10px',
    }}
    >
      <div>{t_i18n('If entity dynamic mapping')}</div>
      <MUIAutocomplete
        selectOnFocus
        openOnFocus
        autoSelect={false}
        autoHighlight
        options={options}
        disabled={true}
        sx={{ width: '240px', marginLeft: '85px' }}
                // onChange={(_, val) => setFieldValue('dynamic_mapping', val)}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            label={t_i18n('Column index')}
            variant="outlined"
            size="small"
          />
        )}
      />
      <Field
        component={TextField}
        name="value"
        label={t_i18n('Value')}
        sx={{ margin: '0px 5px 10px' }}
      />
    </div>
  );
};

export default CsvMapperConditionalEntityMapping;
