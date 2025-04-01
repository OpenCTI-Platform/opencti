import React, { FunctionComponent } from 'react';
import { Field, FieldProps } from 'formik';
import { JsonMapperColumnBasedFormData, JsonMapperRepresentationFormData } from '@components/data/jsonMapper/representations/Representation';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import type { Theme } from '../../../../../components/Theme';

interface JsonMapperConditionalEntityMappingProps
  extends FieldProps<JsonMapperColumnBasedFormData> {
  representation: JsonMapperRepresentationFormData;
  representationName: string;
}

const JsonMapperConditionalEntityMapping: FunctionComponent<
JsonMapperConditionalEntityMappingProps
> = ({ representationName, representation }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const columnBased = representation.column_based;

  return (
    <div style={{
      width: '100%',
      display: 'grid',
      alignItems: 'center',
      marginTop: `${theme.spacing(3)} 0 `,
      marginBottom: 4,
      gap: theme.spacing(1),
    }}
    >
      <Field
        component={TextField}
        label={t_i18n('JSON Entity path')}
        name={`${representationName}.column_based.value`}
        value={columnBased?.enabled ? columnBased.value : ''}
        variant='standard'
        style={{ width: '100%' }}
        error={!columnBased?.value && columnBased?.enabled}
      />
    </div>
  );
};

export default JsonMapperConditionalEntityMapping;
