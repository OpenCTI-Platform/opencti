import React, { createContext, Suspense, useEffect, useMemo, useRef } from 'react';
import { Formik, FormikConfig, FormikValues, useFormikContext } from 'formik';
import { useLazyLoadQuery } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import {
  buildCustomFieldsValidationSchema,
  buildCustomFieldValuesAddInput,
  CustomFieldDef,
  CustomFieldFormValues,
  getCustomFieldsInitialValues,
} from '../../../../utils/customFields';
import { customFieldDefinitionsForEntityTypeQuery } from './CustomFieldsInput';
import { CustomFieldsInputQuery } from './__generated__/CustomFieldsInputQuery.graphql';

export const CustomFieldsCreationContext = createContext<{
  entityType: string;
  definitions: readonly CustomFieldDef[];
}>({ entityType: '', definitions: [] });

type Props<Values> = FormikConfig<Values> & { entityType: string; enabled?: boolean };

// A quick-creation type picker must reset only custom fields, not the user's other inputs.
const CustomFieldsTypeDefaults = ({ entityType, defaults }: { entityType: string; defaults: CustomFieldFormValues }) => {
  const previousType = useRef(entityType);
  const { setFieldValue } = useFormikContext();
  useEffect(() => {
    if (previousType.current !== entityType) {
      previousType.current = entityType;
      setFieldValue('customFields', defaults, false);
    }
  }, [entityType, defaults, setFieldValue]);
  return null;
};

const CustomFieldsForm = <Values extends FormikValues>({
  entityType, definitions, children, onSubmit, initialValues, validationSchema, ...props
}: Props<Values> & { definitions: readonly CustomFieldDef[] }) => {
  const { t_i18n } = useFormatter();
  const defaults = useMemo(() => getCustomFieldsInitialValues(definitions, entityType), [definitions, entityType]);
  const customFieldsSchema = buildCustomFieldsValidationSchema(definitions, entityType, t_i18n('This field is required'));
  const extendSchema = (schema: typeof validationSchema) => (schema ?? Yup.object()).shape({ customFields: customFieldsSchema });
  return (
    <CustomFieldsCreationContext.Provider value={{ entityType, definitions }}>
      <Formik<Values>
        {...props}
        initialValues={{ ...initialValues, customFields: defaults }}
        validationSchema={typeof validationSchema === 'function'
          ? (...args: unknown[]) => extendSchema(validationSchema(...args))
          : extendSchema(validationSchema)}
        onSubmit={({ customFields, ...values }, helpers) => {
          const customFieldValues = buildCustomFieldValuesAddInput(definitions, customFields);
          // Keep UI-only state out of spread-based mutation inputs.
          return onSubmit({ ...values, ...(customFieldValues.length > 0 ? { customFieldValues } : {}) } as unknown as Values, helpers);
        }}
      >
        {(formik) => (
          <>
            <CustomFieldsTypeDefaults entityType={entityType} defaults={defaults} />
            {typeof children === 'function' ? children(formik) : children}
          </>
        )}
      </Formik>
    </CustomFieldsCreationContext.Provider>
  );
};

const CustomFieldsFormWithDefinitions = <Values extends FormikValues>(props: Props<Values>) => {
  const data = useLazyLoadQuery<CustomFieldsInputQuery>(customFieldDefinitionsForEntityTypeQuery, { entityType: props.entityType });
  const definitions = useMemo(() => (data.customFieldDefinitionsForEntityType?.edges ?? []).map(({ node }) => node), [data]);
  return <CustomFieldsForm {...props} definitions={definitions} />;
};

// Wait for definitions before mounting Formik so async defaults cannot erase user input.
const CustomFieldsFormik = <Values extends FormikValues>({ enabled = true, ...props }: Props<Values>) => {
  const { isFeatureEnable } = useHelper();
  if (!enabled) {
    const { entityType: _entityType, ...formikProps } = props;
    return <Formik {...formikProps} />;
  }
  return (
    <Suspense fallback={null}>
      {isFeatureEnable('CUSTOM_FIELDS') && props.entityType
        ? <CustomFieldsFormWithDefinitions {...props} />
        : <CustomFieldsForm {...props} definitions={[]} />}
    </Suspense>
  );
};

export default CustomFieldsFormik;
