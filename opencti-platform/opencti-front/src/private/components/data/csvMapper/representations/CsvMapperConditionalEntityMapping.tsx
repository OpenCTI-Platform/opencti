import React, { FunctionComponent } from 'react';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { Field } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import { CsvMapperColumnBasedFormData, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';

// eslint-disable-next-line @typescript-eslint/no-empty-interface
interface CsvMapperConditionalEntityMappingProps {
  options: string[]
  selectedOption: string
  representation: CsvMapperRepresentationFormData
  representationName: string
}

const CsvMapperConditionalEntityMapping: FunctionComponent<CsvMapperConditionalEntityMappingProps> = ({
  options, selectedOption,
}) => {
  const { t_i18n } = useFormatter();
  // console.log('representation', representation);
  // console.log('representationName', representationName);
  const handleValueSelect = async (
    setFieldValue: FormikHelpers<CsvMapperFormData>['setFieldValue'],
    value: CsvMapperColumnBasedFormData
    ,
  ) => {
    await setFieldValue('value', value);
  };
  const handleColumnSelect = async (
    setFieldValue: FormikHelpers<CsvMapperFormData>['setFieldValue'],
    value: CsvMapperColumnBasedFormData,
  ) => {
    // const newValue: CsvMapperColumnBasedFormData = {
    //   ...value,
    //   column_reference: value.column_reference ?? undefined,
    //   operator: Operator.Eq,
    //   value: 'dd',
    // };
    await setFieldValue('column_reference', value.column_reference ?? undefined);
    await setFieldValue('operator', value.operator ?? undefined);
    await setFieldValue('value', value.value ?? undefined);
  };
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
        value={selectedOption}
        onChange={() => handleColumnSelect}
        sx={{ width: '240px', marginLeft: '85px' }}
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
        onChange={handleValueSelect}
      />
      {/* <MUIAutocomplete */}
      {/*  selectOnFocus */}
      {/*  openOnFocus */}
      {/*  autoSelect={false} */}
      {/*  autoHighlight */}
      {/*  options={operators} */}
      {/*  disabled={true} */}
      {/*  value={selectedOption} */}
      {/*  sx={{ width: '240px', marginLeft: '85px' }} */}
      {/*  renderInput={(params) => ( */}
      {/*    <MuiTextField */}
      {/*      {...params} */}
      {/*      label={t_i18n('Column index')} */}
      {/*      variant="outlined" */}
      {/*      size="small" */}
      {/*    /> */}
      {/*  )} */}
      {/* /> */}
    </div>
  );
};

export default CsvMapperConditionalEntityMapping;
