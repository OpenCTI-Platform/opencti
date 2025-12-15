import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import InputAdornment from '@mui/material/InputAdornment';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { RetentionLinesPaginationQuery$variables } from '@components/settings/retention/__generated__/RetentionLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { RetentionCreationCheckMutation$data } from '@components/settings/retention/__generated__/RetentionCreationCheckMutation.graphql';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { serializeFilterGroupForBackend, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { insertNode } from '../../../../utils/store';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import AutocompleteField from '../../../../components/AutocompleteField';
import SelectField from '../../../../components/fields/SelectField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

const RetentionCreationMutation = graphql`
    mutation RetentionCreationMutation($input: RetentionRuleAddInput!) {
        retentionRuleAdd(input: $input) {
            ...RetentionLine_node
        }
    }
`;

const RetentionCheckMutation = graphql`
    mutation RetentionCreationCheckMutation($input: RetentionRuleAddInput!) {
        retentionRuleCheck(input: $input)
    }
`;

const RetentionCreationValidation = (t: (text: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  retention_unit: Yup.string().required(t('This field is required')),
  max_retention: Yup.number().min(1, t('This field must be >= 1')),
});

const CreateRetentionControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="RetentionRule"
    {...props}
  />
);

interface RetentionFormValues {
  name: string;
  max_retention: string;
  retention_unit: 'minutes' | 'hours' | 'days';
  scope: { value: string; label: string };
  filters: string;
}

const RetentionCreation = ({ paginationOptions }: { paginationOptions: RetentionLinesPaginationQuery$variables }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [filters, helpers] = useFiltersState();
  const [verified, setVerified] = useState(false);
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object', 'stix-core-relationship']);
  const onSubmit: FormikConfig<RetentionFormValues>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const scope = values.scope.value;
    const finalValues = {
      ...values,
      max_retention: Number(values.max_retention),
      scope,
      filters: scope === 'knowledge' ? values.filters : '',
    };
    const jsonFilters = serializeFilterGroupForBackend(filters);
    commitMutation({
      mutation: RetentionCreationMutation,
      variables: {
        input: { ...finalValues, filters: jsonFilters },
      },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_retentionRules',
          paginationOptions,
          'retentionRuleAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
    });
  };

  const handleVerify = (values: RetentionFormValues) => {
    const scope = values.scope.value;
    const finalValues = {
      ...values,
      max_retention: Number(values.max_retention),
      scope,
      filters: scope === 'knowledge' ? values.filters : '',
    };
    const jsonFilters = serializeFilterGroupForBackend(filters);
    commitMutation({
      mutation: RetentionCheckMutation,
      variables: {
        input: { ...finalValues, filters: jsonFilters },
      },
      onCompleted: (data: RetentionCreationCheckMutation$data) => {
        setVerified(true);
        MESSAGING$.notifySuccess(
          t_i18n(`Retention policy will delete ${data.retentionRuleCheck} elements`),
        );
      },
      onError: () => {
        setVerified(false);
      },
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      updater: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <Drawer
      title={t_i18n('Create a retention policy')}
      onClose={helpers.handleClearAllFilters}
      controlledDial={CreateRetentionControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{ name: '', max_retention: '31', retention_unit: 'days', scope: { value: 'knowledge', label: 'Knowledge' }, filters: '' }}
          validationSchema={RetentionCreationValidation(t_i18n)}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, values: formValues, setFieldValue }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="retention_unit"
                label={t_i18n('Unit')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                <MenuItem value="minutes">{t_i18n('minutes')}</MenuItem>
                <MenuItem value="hours">{t_i18n('hours')}</MenuItem>
                <MenuItem value="days">{t_i18n('days')}</MenuItem>
              </Field>
              <Field
                component={TextField}
                variant="standard"
                name="max_retention"
                label={t_i18n('Maximum retention')}
                fullWidth={true}
                onChange={() => setVerified(false)}
                style={{ marginTop: 20 }}
                slotProps={{
                  input: {
                    endAdornment: (
                      <InputAdornment position="end">
                        <Tooltip
                          title={t_i18n(
                            'All objects matching the filters that have not been updated since this amount of units will be deleted',
                          )}
                        >
                          <InformationOutline
                            fontSize="small"
                            color="primary"
                            style={{ cursor: 'default' }}
                          />
                        </Tooltip>
                      </InputAdornment>
                    ),
                  },
                }}
              />
              <Field
                component={AutocompleteField}
                variant="standard"
                name="scope"
                style={{ marginTop: 20 }}
                fullWidth={true}
                onChange={setFieldValue}
                options={[
                  { value: 'knowledge', label: t_i18n('Knowledge') },
                  { value: 'file', label: t_i18n('File') },
                  { value: 'workbench', label: t_i18n('Workbench') },
                ]}
                renderOption={(prop: Record<string, unknown>, option: FieldOption) => (
                  <li {...prop}>
                    <div className={classes.text}>{t_i18n(option.label)}</div>
                  </li>
                )}
                textfieldprops={{
                  label: t_i18n('Scope'),
                }}
              />
              {formValues.scope?.value === 'file'
                && (
                  <Alert severity="info" style={{ margin: '15px 15px 0 15px' }}>
                    {`${t_i18n('The retention policy will be applied on global files (files contained in')} ${t_i18n('Data')}/${t_i18n('Import')})`}
                  </Alert>
                )
              }
              {formValues.scope?.value === 'workbench'
                && (
                  <Alert severity="info" style={{ margin: '15px 15px 0 15px' }}>
                    {`${t_i18n('The retention policy will be applied on global workbenches (workbenches contained in')} ${t_i18n('Data')}/${t_i18n('Import')})`}
                  </Alert>
                )
              }
              {formValues.scope?.value === 'knowledge' && (
                <>
                  <Box sx={{
                    paddingTop: 4,
                    display: 'flex',
                    gap: 1,
                  }}
                  >
                    <Filters
                      availableFilterKeys={availableFilterKeys}
                      helpers={helpers}
                      searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
                    />
                  </Box>
                  <FilterIconButton
                    filters={filters}
                    helpers={helpers}
                    styleNumber={2}
                    redirection
                    searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
                  />
                </>
              )}
              <div className={classes.buttons}>
                <Button
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  color="secondary"
                  onClick={() => handleVerify(formValues)}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Verify')}
                </Button>
                <Button
                  color="secondary"
                  onClick={submitForm}
                  disabled={!verified || isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default RetentionCreation;
