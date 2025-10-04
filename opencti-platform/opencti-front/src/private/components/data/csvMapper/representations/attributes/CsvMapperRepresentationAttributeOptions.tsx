import React, { FunctionComponent } from 'react';
import DialogContentText from '@mui/material/DialogContentText';
import { Field, FormikProps } from 'formik';
import DefaultValueField from '@private/components/common/form/DefaultValueField';
import { CsvMapperFormData } from '@private/components/data/csvMapper/CsvMapper';
import { SchemaAttribute } from '@private/components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import CsvMapperDefaultMarking from '@private/components/data/csvMapper/representations/attributes/CsvMapperDefaultMarking';
import CsvMapperRepresentationAttributeOption from './CsvMapperRepresentationAttributeOption';
import { useFormatter } from '../../../../../../components/i18n';

interface CsvMapperRepresentationAttributeOptionsProps {
  schemaAttribute: SchemaAttribute;
  attributeName: string;
  form: FormikProps<CsvMapperFormData>
}

const CsvMapperRepresentationAttributeOptions: FunctionComponent<CsvMapperRepresentationAttributeOptionsProps> = ({ schemaAttribute, attributeName, form }) => {
  const { t_i18n } = useFormatter();
  const { setFieldValue, getFieldProps } = form;

  const settingsDefaultValues = (schemaAttribute.defaultValues?.length ?? 0) > 0;

  // Retrieve the entity type of the current representation for open vocab fields.
  const representationName = attributeName.split('.')[0];
  const entityType: string = getFieldProps(representationName).value.target_type;

  return (
    <>
      {schemaAttribute.type === 'date' && (
        <Field
          component={CsvMapperRepresentationAttributeOption}
          name={`${attributeName}.pattern_date`}
          placeholder={t_i18n('Date pattern')}
          tooltip={t_i18n(
            'By default we accept iso date (YYYY-MM-DD), but you can specify your own date format in ISO notation (for instance DD.MM.YYYY)',
          )}
        />
      )}
      {schemaAttribute.multiple && (
        <Field
          component={CsvMapperRepresentationAttributeOption}
          name={`${attributeName}.separator`}
          placeholder={t_i18n('List separator')}
          tooltip={t_i18n(
            'If this field contains multiple values, you can specify the separator used between each values (for instance | or +)',
          )}
        />
      )}
      {schemaAttribute.editDefault && (
        <>
          {schemaAttribute.name === 'objectMarking' ? (
            <CsvMapperDefaultMarking
              name={`${attributeName}.default_values`}
            />
          ) : (
            <DefaultValueField
              attribute={schemaAttribute}
              setFieldValue={setFieldValue}
              name={`${attributeName}.default_values`}
              entityType={entityType}
            />
          )}

          {settingsDefaultValues
            ? (
              <DialogContentText>
                {t_i18n('Settings default values usage...')}
              </DialogContentText>
            )
            : (
              <DialogContentText sx={{ width: 450, mt: '8px' }}>
                {t_i18n('No default value set in Settings...')}
              </DialogContentText>
            )
          }
        </>
      )}
    </>
  );
};

export default CsvMapperRepresentationAttributeOptions;
