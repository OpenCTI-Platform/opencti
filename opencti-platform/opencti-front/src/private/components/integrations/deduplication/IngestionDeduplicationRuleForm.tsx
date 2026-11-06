import React from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import CreatorField from '@components/common/form/CreatorField';
import ComboboxField from '../../../../components/ComboboxField';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { MESSAGING$ } from '../../../../relay/environment';

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

export const DEFAULT_EXCLUDED_FIELDS = ['modified', 'x_opencti_modified_at'];

export interface IngestionDeduplicationRuleValue {
  id: string;
  user_id: string;
  target_type: string;
  excluded_fields: readonly string[];
}

interface IngestionDeduplicationRuleFormValues {
  user: FieldOption | null;
  target_type: FieldOption | null;
  excluded_fields: FieldOption[];
}

interface IngestionDeduplicationRuleFormProps {
  open: boolean;
  onClose: () => void;
  onCompleted: () => void;
  allowedTypes: readonly string[];
  // Fixed when the rule is managed from a connector, picked in the form otherwise
  userId?: string | null;
  rule?: IngestionDeduplicationRuleValue | null;
}

const toOption = (value: string): FieldOption => ({ value, label: value });

const IngestionDeduplicationRuleForm = ({ open, onClose, onCompleted, allowedTypes, userId, rule }: IngestionDeduplicationRuleFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitAdd] = useApiMutation(ingestionDeduplicationRuleAddMutation);
  const [commitPatch] = useApiMutation(ingestionDeduplicationRulePatchMutation);
  const isUserPicked = !userId && !rule;

  const typeOptions = allowedTypes.map((type) => ({ value: type, label: t_i18n(`entity_${type}`) }));
  const initialValues: IngestionDeduplicationRuleFormValues = {
    user: null,
    target_type: rule ? typeOptions.find((option) => option.value === rule.target_type) ?? null : null,
    excluded_fields: (rule ? rule.excluded_fields : DEFAULT_EXCLUDED_FIELDS).map(toOption),
  };

  const onSubmit = (values: IngestionDeduplicationRuleFormValues, { setSubmitting }: { setSubmitting: (isSubmitting: boolean) => void }) => {
    const targetType = values.target_type?.value as string;
    const excludedFields = values.excluded_fields.map((option) => String(option.value));
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
            { key: 'target_type', value: [targetType] },
            { key: 'excluded_fields', value: excludedFields },
          ],
        },
        ...callbacks,
      });
    } else {
      commitAdd({
        variables: {
          input: {
            user_id: userId ?? values.user?.value,
            target_type: targetType,
            excluded_fields: excludedFields,
          },
        },
        ...callbacks,
      });
    }
  };

  return (
    <Drawer
      title={rule ? t_i18n('Update a deduplication rule') : t_i18n('Add a deduplication rule')}
      open={open}
      onClose={onClose}
    >
      <Formik<IngestionDeduplicationRuleFormValues>
        enableReinitialize
        initialValues={initialValues}
        validationSchema={Yup.object().shape({
          user: isUserPicked ? Yup.object().required(t_i18n('This field is required')) : Yup.object().nullable(),
          target_type: Yup.object().required(t_i18n('This field is required')),
        })}
        onSubmit={onSubmit}
        onReset={onClose}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form>
            {isUserPicked && (
              <CreatorField
                name="user"
                label={t_i18n('User')}
                onChange={setFieldValue}
                required
              />
            )}
            <Field
              component={ComboboxField}
              name="target_type"
              style={isUserPicked ? fieldSpacingContainerStyle : undefined}
              options={typeOptions}
              renderOption={(option: FieldOption) => (
                <>
                  <ItemIcon type={String(option.value)} />
                  <span style={{ padding: '0 4px' }}>{option.label}</span>
                </>
              )}
              label={t_i18n('Entity type')}
              required
            />
            <Field
              component={AutocompleteFreeSoloField}
              style={fieldSpacingContainerStyle}
              name="excluded_fields"
              multiple={true}
              createLabel={t_i18n('Add')}
              textfieldprops={{
                variant: 'outlined',
                label: t_i18n('Excluded fields'),
                helperText: t_i18n('Changes to these fields alone do not trigger a new import'),
              }}
              options={DEFAULT_EXCLUDED_FIELDS.map(toOption)}
              renderOption={(option: FieldOption) => <div>{option.label}</div>}
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
    </Drawer>
  );
};

export default IngestionDeduplicationRuleForm;
