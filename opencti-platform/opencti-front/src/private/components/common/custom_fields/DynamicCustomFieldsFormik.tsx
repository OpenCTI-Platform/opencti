import { ReactNode, Suspense, useCallback, useState } from 'react';
import { Formik, FormikConfig, FormikErrors, FormikValues, useFormikContext, yupToFormErrors } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import {
  buildCustomFieldsValidationSchema,
  buildCustomFieldValuesAddInput,
  CustomFieldDef,
  CustomFieldFormValues,
  getCustomFieldsInitialValues,
} from '../../../../utils/customFields';
import { CustomFieldsCreationContext } from './CustomFieldsFormik';
import { customFieldDefinitionsForEntityTypeQuery, CustomFieldsLoader } from './CustomFieldsInput';
import { CustomFieldsInputQuery } from './__generated__/CustomFieldsInputQuery.graphql';

interface LoadedDefinitions {
  entityType: string;
  definitions: CustomFieldDef[];
}

const fetchDefinitions = async (entityType: string): Promise<CustomFieldDef[]> => {
  const data = await fetchQuery<CustomFieldsInputQuery>(customFieldDefinitionsForEntityTypeQuery, { entityType }).toPromise();
  return (data?.customFieldDefinitionsForEntityType?.edges ?? []).map(({ node }) => node);
};

// Keep the form mounted while the type picker loads a new set of definitions.
const DynamicFields = ({ typeField, loaded, onLoaded, children }: {
  typeField: string;
  loaded: LoadedDefinitions;
  onLoaded: (loaded: LoadedDefinitions) => void;
  children: ReactNode;
}) => {
  const { values, setFieldValue } = useFormikContext<FormikValues>();
  const entityType = String(values[typeField] ?? '');
  const loadDefinitions = useCallback((definitions: CustomFieldDef[]) => {
    setFieldValue('customFields', getCustomFieldsInitialValues(definitions, entityType), false);
    onLoaded({ entityType, definitions });
  }, [entityType, onLoaded, setFieldValue]);
  return (
    <CustomFieldsCreationContext.Provider value={{
      entityType,
      definitions: loaded.entityType === entityType ? loaded.definitions : [],
    }}
    >
      {entityType && (
        <Suspense fallback={null}>
          <CustomFieldsLoader key={entityType} entityType={entityType} onLoaded={loadDefinitions} />
        </Suspense>
      )}
      {children}
    </CustomFieldsCreationContext.Provider>
  );
};

type Props<Values> = FormikConfig<Values> & { typeField: string; enabled?: boolean };

const DynamicCustomFieldsFormik = <Values extends FormikValues>({
  typeField, enabled = true, initialValues, children, onSubmit, validate, ...props
}: Props<Values>) => {
  const { t_i18n } = useFormatter();
  const [loaded, setLoaded] = useState<LoadedDefinitions>({ entityType: '', definitions: [] });
  // A submit made while the definitions of the selected type load waits for them and uses their
  // defaults: it is neither dropped nor sent with the defaults of the previous type.
  const resolveCustomFields = async (entityType: string, customFields: CustomFieldFormValues) => {
    if (loaded.entityType === entityType) return { definitions: loaded.definitions, customFields };
    const definitions = await fetchDefinitions(entityType);
    return { definitions, customFields: getCustomFieldsInitialValues(definitions, entityType) };
  };
  return (
    <Formik<Values>
      {...props}
      initialValues={{ ...initialValues, customFields: {} }}
      validate={async (values) => {
        const errors = await validate?.(values) ?? {};
        const entityType = String(values[typeField] ?? '');
        if (!enabled || !entityType) return errors;
        const { definitions, customFields } = await resolveCustomFields(entityType, values.customFields);
        try {
          await buildCustomFieldsValidationSchema(definitions, entityType, t_i18n)
            .validate(customFields, { abortEarly: false });
          return errors;
        } catch (error) {
          return { ...errors, customFields: yupToFormErrors(error) } as unknown as FormikErrors<Values>;
        }
      }}
      onSubmit={({ customFields, ...values }, helpers) => {
        const entityType = String(values[typeField] ?? '');
        const submit = (definitions: CustomFieldDef[], customFieldsValues: CustomFieldFormValues) => {
          const customFieldValues = enabled && entityType ? buildCustomFieldValuesAddInput(definitions, customFieldsValues) : [];
          return onSubmit({ ...values, ...(customFieldValues.length ? { customFieldValues } : {}) } as unknown as Values, helpers);
        };
        // Stay synchronous when no wait is needed: consumers end the submission themselves (setSubmitting
        // in their mutation callbacks), and a returned promise would make Formik end it as soon as it settles.
        if (!enabled || !entityType || loaded.entityType === entityType) {
          return submit(loaded.definitions, customFields);
        }
        resolveCustomFields(entityType, customFields)
          .then((resolved) => submit(resolved.definitions, resolved.customFields))
          .catch(() => helpers.setSubmitting(false));
        return undefined;
      }}
    >
      {(formik) => enabled ? (
        <DynamicFields typeField={typeField} loaded={loaded} onLoaded={setLoaded}>
          {typeof children === 'function' ? children(formik) : children}
        </DynamicFields>
      ) : (typeof children === 'function' ? children(formik) : children)}
    </Formik>
  );
};

export default DynamicCustomFieldsFormik;
