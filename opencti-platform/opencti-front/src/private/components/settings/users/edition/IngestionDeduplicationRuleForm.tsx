import React, { Suspense } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import ComboboxField from '../../../../../components/ComboboxField';
import TextField from '../../../../../components/TextField';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import { MESSAGING$ } from '../../../../../relay/environment';
import { IngestionDeduplicationRuleFormFieldsQuery } from './__generated__/IngestionDeduplicationRuleFormFieldsQuery.graphql';

const ingestionDeduplicationRuleAddMutation = graphql`
  mutation IngestionDeduplicationRuleFormAddMutation($input: IngestionDeduplicationRuleAddInput!) {
    ingestionDeduplicationRuleAdd(input: $input) {
      id
    }
  }
`;

const ingestionDeduplicationRulePatchMutation = graphql`
  mutation IngestionDeduplicationRuleFormPatchMutation($id: ID!, $input: [EditInput!]!) {
    ingestionDeduplicationRuleFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const ingestionDeduplicationRuleFieldsQuery = graphql`
  query IngestionDeduplicationRuleFormFieldsQuery($entityType: String!) {
    ingestionDeduplicationFields(entityType: $entityType)
  }
`;

export interface IngestionDeduplicationRuleValue {
  id: string;
  target_type: string;
  excluded_fields: readonly string[];
  ttl?: number | null;
}

interface IngestionDeduplicationRuleFormValues {
  target_type: FieldOption | null;
  excluded_fields: FieldOption[];
  ttl: number | '';
}

interface IngestionDeduplicationRuleFormProps {
  userId: string;
  allowedTypes: readonly string[];
  defaultTtl: number;
  defaultExcludedFields: readonly string[];
  rule?: IngestionDeduplicationRuleValue | null;
  onClose: () => void;
  onCompleted: () => void;
}

const toOption = (value: string): FieldOption => ({ value, label: value });

interface ExcludedFieldsFieldProps {
  entityType: string;
  label: string;
  helperText: string;
}

// The options are the fields of the import input of the type, the ones the platform compares
const ExcludedFieldsField = ({ entityType, label, helperText }: ExcludedFieldsFieldProps) => {
  const data = useLazyLoadQuery<IngestionDeduplicationRuleFormFieldsQuery>(
    ingestionDeduplicationRuleFieldsQuery,
    { entityType },
    { fetchPolicy: 'store-or-network' },
  );
  return (
    <Field
      component={ComboboxField}
      name="excluded_fields"
      multiple
      style={fieldSpacingContainerStyle}
      options={data.ingestionDeduplicationFields.map(toOption)}
      label={label}
      helperText={helperText}
    />
  );
};

const IngestionDeduplicationRuleForm = ({ userId, allowedTypes, defaultTtl, defaultExcludedFields, rule, onClose, onCompleted }: IngestionDeduplicationRuleFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitAdd] = useApiMutation(ingestionDeduplicationRuleAddMutation);
  const [commitPatch] = useApiMutation(ingestionDeduplicationRulePatchMutation);

  const typeOptions = allowedTypes.map((type) => ({ value: type, label: t_i18n(`entity_${type}`) }));
  const initialValues: IngestionDeduplicationRuleFormValues = {
    target_type: rule ? typeOptions.find((option) => option.value === rule.target_type) ?? null : null,
    excluded_fields: (rule ? rule.excluded_fields : defaultExcludedFields).map(toOption),
    ttl: rule?.ttl ?? '',
  };

  const onSubmit = (values: IngestionDeduplicationRuleFormValues, { setSubmitting }: { setSubmitting: (isSubmitting: boolean) => void }) => {
    const targetType = values.target_type?.value as string;
    const excludedFields = values.excluded_fields.map((option) => String(option.value));
    const ttl = values.ttl === '' ? null : Number(values.ttl);
    const callbacks = {
      onError: () => setSubmitting(false),
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess(t_i18n('The deduplication rule has been saved'));
        onCompleted();
        onClose();
      },
    };
    if (rule) {
      commitPatch({
        variables: {
          id: rule.id,
          input: [
            { key: 'excluded_fields', value: excludedFields },
            { key: 'ttl', value: [ttl] },
          ],
        },
        ...callbacks,
      });
    } else {
      commitAdd({
        variables: { input: { user_id: userId, target_type: targetType, excluded_fields: excludedFields, ttl } },
        ...callbacks,
      });
    }
  };

  return (
    <Formik<IngestionDeduplicationRuleFormValues>
      initialValues={initialValues}
      validationSchema={Yup.object().shape({
        target_type: Yup.object().required(t_i18n('This field is required')),
        ttl: Yup.number().transform((value, original) => (original === '' ? undefined : value)).integer(t_i18n('The value must be an integer')).positive(t_i18n('The value must be greater than 0')),
      })}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ values, submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Typography variant="h4" gutterBottom>
            {rule ? t_i18n('Update a deduplication rule') : t_i18n('Add a deduplication rule')}
          </Typography>
          <Field
            component={ComboboxField}
            name="target_type"
            options={typeOptions}
            renderOption={(option: FieldOption) => (
              <>
                <ItemIcon type={String(option.value)} />
                <span style={{ padding: '0 4px' }}>{option.label}</span>
              </>
            )}
            label={t_i18n('Entity type')}
            required
            disabled={!!rule}
          />
          {values.target_type ? (
            <Suspense fallback={null}>
              <ExcludedFieldsField
                key={String(values.target_type.value)}
                entityType={String(values.target_type.value)}
                label={t_i18n('Excluded fields')}
                helperText={t_i18n('Changes to these fields alone do not trigger a new import')}
              />
            </Suspense>
          ) : (
            <Field
              component={ComboboxField}
              name="excluded_fields"
              multiple
              disabled
              style={fieldSpacingContainerStyle}
              options={[]}
              label={t_i18n('Excluded fields')}
              helperText={t_i18n('Choose an entity type to see its fields')}
            />
          )}
          <Field
            component={TextField}
            variant="outlined"
            type="number"
            name="ttl"
            label={t_i18n('Expiration (seconds)')}
            helperText={`${t_i18n('After this delay, the next import runs even if nothing changed. Leave empty for the platform default:')} ${defaultTtl} s`}
            fullWidth
            style={fieldSpacingContainerStyle}
          />
          <div style={{ marginTop: theme.spacing(2), gap: theme.spacing(1), display: 'flex', justifyContent: 'flex-end' }}>
            <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
              {t_i18n('Cancel')}
            </Button>
            <Button onClick={submitForm} disabled={isSubmitting}>
              {rule ? t_i18n('Update') : t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default IngestionDeduplicationRuleForm;
