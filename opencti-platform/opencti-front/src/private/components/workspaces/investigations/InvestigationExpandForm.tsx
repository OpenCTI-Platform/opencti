import { Button, Text } from '@filigran/design-system';
import { DialogActions, Stack } from '@mui/material';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import CheckboxesField from '../../../../components/CheckboxesField';
import SwitchField from '../../../../components/fields/SwitchField';
import { FieldOption } from '../../../../utils/field';

type InvestigationExpandFormData = {
  entity_types: FieldOption[];
  relationship_types: FieldOption[];
  reset_filters: boolean;
};

export interface InvestigationExpandFormProps {
  disabled?: boolean;
  targets: FieldOption[];
  relationships: FieldOption[];
  onDismiss?: () => void;
  onReset: () => void;
  onSubmit: (
    data: InvestigationExpandFormData,
    helpers: FormikHelpers<InvestigationExpandFormData>,
  ) => void;
}

const InvestigationExpandForm = ({
  targets,
  relationships,
  onDismiss,
  onReset,
  onSubmit,
  disabled = false,
}: InvestigationExpandFormProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Formik<InvestigationExpandFormData>
      enableReinitialize={true}
      initialValues={{
        entity_types: [],
        relationship_types: [],
        reset_filters: true,
      }}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Stack spacing={3} sx={{ p: 3 }}>
            <Stack
              direction="row"
              sx={{ justifyContent: 'space-between' }}
            >
              <Field
                name="entity_types"
                component={CheckboxesField}
                label={t_i18n('All types of target')}
                items={targets}
                disabled={disabled}
              />
              <Field
                name="relationship_types"
                component={CheckboxesField}
                label={t_i18n('All types of relationship')}
                items={relationships}
                disabled={disabled}
              />
            </Stack>

            <Field
              component={SwitchField}
              type="checkbox"
              name="reset_filters"
              label={t_i18n('Reset filters')}
              containerstyle={{ marginTop: 12 }}
              disabled={disabled}
            />

            <Text variant="content-compact">
              {t_i18n('You have view access to this investigation: you can see the results but not add or dismiss them')}
            </Text>

            <DialogActions>
              {onDismiss && (
                <>
                  <Button
                    priority="tertiary"
                    onClick={onDismiss}
                    disabled={isSubmitting || disabled}
                  >
                    {t_i18n('Dismiss')}
                  </Button>
                  <div style={{ flex: 1 }} />
                </>
              )}
              <Button
                priority="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting || disabled}
              >
                {t_i18n('Expand')}
              </Button>
            </DialogActions>
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default InvestigationExpandForm;
