import { FunctionComponent, Suspense, useRef, useState } from 'react';
import Divider from '@mui/material/Divider';
import { useFormikContext } from 'formik';
import { graphql } from 'react-relay';
import {
  CustomFieldDef,
  CustomFieldStoredValue,
  CustomFieldValue,
  getCustomFieldCurrentValue,
  getCustomFieldSetting,
  updateCustomFieldValues,
} from '../../../../utils/customFields';
import type useFormEditor from '../../../../utils/hooks/useFormEditor';
import useHelper from '../../../../utils/hooks/useHelper';
import { CustomFieldInput, CustomFieldsLoader } from './CustomFieldsInput';

// Unmasked in entity overview fragments so their existing mutations/subscriptions refresh values.
export const customFieldValuesEditionFragment = graphql`
  fragment CustomFieldValuesEdition_values on StixDomainObject {
    entity_type
    customFieldValues {
      field_id
      field_name
      int_value
      string_value
      boolean_value
      date_value
      select_value
      select_values
    }
  }
`;

interface CustomFieldValuesEditionProps {
  entityType: string;
  entityId: string;
  values: readonly CustomFieldStoredValue[];
  fieldPatch: ReturnType<typeof useFormEditor>['fieldPatch'];
  enableReferences?: boolean;
}

const CustomFieldValuesEdition: FunctionComponent<CustomFieldValuesEditionProps> = ({ entityType, entityId, values, fieldPatch, enableReferences = false }) => {
  const { isFeatureEnable } = useHelper();
  const [definitions, setDefinitions] = useState<CustomFieldDef[]>([]);
  const formik = useFormikContext<{ custom_field_values?: readonly CustomFieldStoredValue[] }>();
  const [pendingValues, setPendingValues] = useState<readonly CustomFieldStoredValue[] | null>(null);
  const acknowledgedValues = useRef(values);
  const pendingChanges = useRef<{ definition: CustomFieldDef; rawValue: CustomFieldValue }[]>([]);
  const saving = useRef(false);
  if (!saving.current && pendingChanges.current.length === 0) acknowledgedValues.current = values;
  const currentValues = enableReferences ? formik.values.custom_field_values ?? values : pendingValues ?? values;

  const stageValue = (definition: CustomFieldDef, rawValue: CustomFieldValue) => {
    formik.setValues((previous) => ({
      ...previous,
      custom_field_values: updateCustomFieldValues(definition, rawValue, previous.custom_field_values ?? values),
    }));
  };

  // Replacements must be serialized: a second field edit must not overwrite an in-flight first one.
  const flushChanges = () => {
    if (saving.current || pendingChanges.current.length === 0) return;
    const changes = pendingChanges.current.splice(0);
    const nextValues = changes.reduce<readonly CustomFieldStoredValue[]>(
      (previous, { definition, rawValue }) => updateCustomFieldValues(definition, rawValue, previous),
      acknowledgedValues.current,
    );
    saving.current = true;
    fieldPatch({
      variables: {
        id: entityId,
        input: { key: 'custom_field_values', value: nextValues },
      },
      onCompleted: () => {
        acknowledgedValues.current = nextValues;
        saving.current = false;
        if (pendingChanges.current.length > 0) flushChanges();
        else setPendingValues(null);
      },
      onError: () => {
        saving.current = false;
        pendingChanges.current = [];
        setPendingValues(null);
      },
    });
  };

  const handleSubmit = (definition: CustomFieldDef, rawValue: CustomFieldValue) => {
    setPendingValues((previous) => updateCustomFieldValues(definition, rawValue, previous ?? values));
    pendingChanges.current.push({ definition, rawValue });
    flushChanges();
  };

  if (!isFeatureEnable('CUSTOM_FIELDS')) return null;

  return (
    <>
      {isFeatureEnable('CUSTOM_FIELDS') && (
        <Suspense fallback={null}>
          <CustomFieldsLoader entityType={entityType} onLoaded={setDefinitions} />
        </Suspense>
      )}
      {definitions.length > 0 && (
        <>
          <Divider style={{ marginTop: 20 }} />
          {definitions.map((definition) => (
            <CustomFieldInput
              key={definition.id}
              definition={definition}
              mandatory={getCustomFieldSetting(definition, entityType)?.mandatory ?? false}
              value={getCustomFieldCurrentValue(definition, currentValues)}
              onChange={enableReferences ? (value) => stageValue(definition, value) : undefined}
              onSubmit={enableReferences ? undefined : (value) => handleSubmit(definition, value)}
            />
          ))}
        </>
      )}
    </>
  );
};

export default CustomFieldValuesEdition;
