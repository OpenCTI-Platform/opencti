import { ReactNode, Suspense, useCallback, useState } from 'react';
import { Formik, FormikConfig, FormikErrors, FormikValues, useFormikContext, yupToFormErrors } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { buildCustomFieldsValidationSchema, buildCustomFieldValuesAddInput, CustomFieldDef, getCustomFieldsInitialValues } from '../../../../utils/customFields';
import { CustomFieldsCreationContext } from './CustomFieldsFormik';
import { CustomFieldsLoader } from './CustomFieldsInput';

interface LoadedDefinitions {
  entityType: string;
  definitions: CustomFieldDef[];
}

// Keep the form mounted while the type picker loads a new set of definitions.
const DynamicFields = ({ typeField, loaded, onLoaded, children }: {
  typeField: string;
  loaded: LoadedDefinitions;
  onLoaded: (loaded: LoadedDefinitions) => void;
  children: ReactNode;
}) => {
  const { values, setFieldValue } = useFormikContext<FormikValues>();
  const entityType = String(values[typeField] ?? '');
  const { isFeatureEnable } = useHelper();
  const enabled = isFeatureEnable('CUSTOM_FIELDS');
  const loadDefinitions = useCallback((definitions: CustomFieldDef[]) => {
    setFieldValue('customFields', getCustomFieldsInitialValues(definitions, entityType), false);
    onLoaded({ entityType, definitions });
  }, [entityType, onLoaded, setFieldValue]);
  return (
    <CustomFieldsCreationContext.Provider value={{
      entityType,
      definitions: enabled && loaded.entityType === entityType ? loaded.definitions : [],
    }}
    >
      {enabled && entityType && (
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
  const { isFeatureEnable } = useHelper();
  const [loaded, setLoaded] = useState<LoadedDefinitions>({ entityType: '', definitions: [] });
  const active = enabled && isFeatureEnable('CUSTOM_FIELDS');
  return (
    <Formik<Values>
      {...props}
      initialValues={{ ...initialValues, customFields: {} }}
      validate={async (values) => {
        const errors = await validate?.(values) ?? {};
        const entityType = String(values[typeField] ?? '');
        if (!active || !entityType) return errors;
        // Do not submit defaults from the previous type while the next query is pending.
        if (loaded.entityType !== entityType) {
          return { ...errors, customFields: t_i18n('Loading') } as FormikErrors<Values>;
        }
        try {
          await buildCustomFieldsValidationSchema(loaded.definitions, entityType, t_i18n('This field is required'))
            .validate(values.customFields, { abortEarly: false });
          return errors;
        } catch (error) {
          return { ...errors, customFields: yupToFormErrors(error) } as unknown as FormikErrors<Values>;
        }
      }}
      onSubmit={({ customFields, ...values }, helpers) => {
        const customFieldValues = active ? buildCustomFieldValuesAddInput(loaded.definitions, customFields) : [];
        return onSubmit({ ...values, ...(customFieldValues.length ? { customFieldValues } : {}) } as unknown as Values, helpers);
      }}
    >
      {(formik) => active ? (
        <DynamicFields typeField={typeField} loaded={loaded} onLoaded={setLoaded}>
          {typeof children === 'function' ? children(formik) : children}
        </DynamicFields>
      ) : (typeof children === 'function' ? children(formik) : children)}
    </Formik>
  );
};

export default DynamicCustomFieldsFormik;
