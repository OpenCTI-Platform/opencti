import React, { FunctionComponent } from 'react';
import DialogContentText from '@mui/material/DialogContentText';
import { Field, FormikProps } from 'formik';
import DefaultValueField from '@components/common/form/DefaultValueField';
import { JsonMapperFormData } from '@components/data/jsonMapper/JsonMapper';
import { SchemaAttribute } from '@components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributesForm';
import JsonMapperDefaultMarking from '@components/data/jsonMapper/representations/attributes/JsonMapperDefaultMarking';
import JsonMapperRepresentationAttributeOption from './JsonMapperRepresentationAttributeOption';
import { useFormatter } from '../../../../../../components/i18n';

interface JsonMapperRepresentationAttributeOptionsProps {
  schemaAttribute: SchemaAttribute;
  baseAttributeName: string;
  configurationAttributeName: string;
  form: FormikProps<JsonMapperFormData>
}

const JsonMapperRepresentationAttributeOptions: FunctionComponent<JsonMapperRepresentationAttributeOptionsProps> = (args) => {
  const { t_i18n } = useFormatter();
  const { schemaAttribute, baseAttributeName, configurationAttributeName, form } = args;
  const { setFieldValue, getFieldProps } = form;

  const settingsDefaultValues = (schemaAttribute.defaultValues?.length ?? 0) > 0;

  // Retrieve the entity type of the current representation for open vocab fields.
  const representationName = baseAttributeName.split('.')[0];
  const { value } = getFieldProps(representationName);
  const entityType: string = value.target?.entity_type;

  return (
    <>
      {schemaAttribute.type === 'date' && (
      <Field
        component={JsonMapperRepresentationAttributeOption}
        name={`${configurationAttributeName}.pattern_date`}
        placeholder={t_i18n('Date pattern')}
        tooltip={t_i18n(
          'By default we accept iso date (YYYY-MM-DD), but you can specify your own date format in ISO notation (for instance DD.MM.YYYY)',
        )}
      />
      )}
      {schemaAttribute.multiple && (
      <Field
        component={JsonMapperRepresentationAttributeOption}
        name={`${configurationAttributeName}.separator`}
        placeholder={t_i18n('List separator')}
        tooltip={t_i18n(
          'If this field contains multiple values, you can specify the separator used between each values (for instance | or +)',
        )}
      />
      )}
      {schemaAttribute.editDefault && (
      <>
        {schemaAttribute.name === 'objectMarking' ? (
          <JsonMapperDefaultMarking
            name={`${baseAttributeName}.default_values`}
          />
        ) : (
          <DefaultValueField
            attribute={schemaAttribute}
            setFieldValue={setFieldValue}
            name={`${baseAttributeName}.default_values`}
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

export default JsonMapperRepresentationAttributeOptions;
