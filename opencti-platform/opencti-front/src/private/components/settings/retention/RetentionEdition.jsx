import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import InputAdornment from '@mui/material/InputAdornment';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Button from '@common/button/Button';
import Box from '@mui/material/Box';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { adaptFieldValue } from '../../../../utils/String';
import {
  deserializeFilterGroupForFrontend,
  isFilterGroupNotEmpty,
  serializeFilterGroupForBackend,
  useAvailableFilterKeysForEntityTypes,
} from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import Drawer from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import SelectField from '../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useTheme } from '@mui/material/styles';
import SwitchField from '../../../../components/fields/SwitchField';

const retentionMutationFieldPatch = graphql`
    mutation RetentionEditionFieldPatchMutation($id: ID!, $input: [EditInput]!) {
        retentionRuleEdit(id: $id) {
            fieldPatch(input: $input) {
                ...RetentionEdition_retentionRule
            }
        }
    }
`;

const RetentionCheckMutation = graphql`
    mutation RetentionEditionCheckMutation($input: RetentionRuleAddInput!) {
        retentionRuleCheck(input: $input)
    }
`;

const RetentionEditionContainer = (props) => {
  const { open, handleClose, retentionRule } = props;
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const initialValues = {
    name: retentionRule.name,
    max_retention: retentionRule.max_retention,
    retention_unit: retentionRule.retention_unit,
    active: retentionRule.active,
  };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(props.retentionRule?.filters ?? undefined));
  const [verified, setVerified] = useState(false);
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object', 'stix-core-relationship']);

  const retentionValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    max_retention: Yup.number().min(1, t_i18n('This field must be >= 1')),
    active: Yup.boolean(),
  });

  const onSubmit = (values, { setSubmitting }) => {
    const inputValues = Object.entries({
      ...values,
      filters: isFilterGroupNotEmpty(filters) ? serializeFilterGroupForBackend(filters) : '',
    })
      .map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    commitMutation({
      mutation: retentionMutationFieldPatch,
      variables: {
        id: props.retentionRule.id,
        input: inputValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleVerify = (values) => {
    const finalValues = {
      ...values,
      max_retention: Number(values.max_retention),
      scope: retentionRule.scope,
    };
    const jsonFilters = serializeFilterGroupForBackend(filters);
    commitMutation({
      mutation: RetentionCheckMutation,
      variables: {
        input: { ...finalValues, filters: jsonFilters },
      },
      onCompleted: (data) => {
        setVerified(true);
        MESSAGING$.notifySuccess(
          t_i18n(`Retention policy will delete ${data.retentionRuleCheck} elements`),
        );
      },
      onError: () => {
        setVerified(false);
      },
    });
  };
  return (
    <Drawer
      title={t_i18n('Update a retention policy')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={retentionValidation}
        onSubmit={onSubmit}
      >
        {({ isSubmitting, submitForm, values: formValues, validateForm, setTouched }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              onChange={() => setVerified(false)}
              fullWidth={true}
              mandatory
            />
            <Field
              component={SelectField}
              variant="standard"
              name="retention_unit"
              label={t_i18n('Unit')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
              onChange={() => setVerified(false)}
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
              onChange={() => setVerified(false)}
              fullWidth={true}
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
              component={SwitchField}
              type="checkbox"
              name="active"
              label={t_i18n('Active')}
              containerstyle={{ marginTop: 20 }}
            />
            {retentionRule.scope === 'activity'
              && (
                <Alert severity="info" style={{ margin: '15px 15px 0 15px' }}>
                  {t_i18n('The retention policy will be applied on activity logs (administration events such as login, logout, and security actions)')}
                </Alert>
              )
            }
            {retentionRule.scope === 'file'
              && (
                <Alert severity="info" style={{ margin: '15px 15px 0 15px' }}>
                  {`${t_i18n('The retention policy will be applied on global files (files contained in')} ${t_i18n('Data')}/${t_i18n('Import')})`}
                </Alert>
              )
            }
            {retentionRule.scope === 'workbench'
              && (
                <Alert severity="info" style={{ margin: '15px 15px 0 15px' }}>
                  {t_i18n('The retention policy will be applied on all workbenches (both global and entity-attached)')}
                </Alert>
              )
            }
            {retentionRule.scope === 'knowledge'
              && (
                <>
                  <Box
                    sx={{
                      paddingTop: 4,
                      display: 'flex',
                      alignItems: 'center',
                      gap: theme.spacing(1),
                      marginBottom: theme.spacing(1),
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
                    redirection
                    searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
                  />
                </>
              )
            }
            {retentionRule.scope === 'history'
              && (
                <Alert severity="info" style={{ margin: '15px 0 15px 0' }}>
                  {t_i18n('The retention policy will be applied on history logs of knowledge entities')}
                </Alert>
              )
            }
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', marginTop: theme.spacing(2) }}>
              <Button
                color="secondary"
                onClick={async () => {
                  const errors = await validateForm();
                  setTouched({ name: true, retention_unit: true, max_retention: true });
                  if (Object.keys(errors).length === 0) {
                    handleVerify(formValues);
                  }
                }}
                disabled={isSubmitting}
                sx={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Verify')}
              </Button>
              <Button
                color="primary"
                onClick={submitForm}
                sx={{ marginLeft: theme.spacing(2) }}
                disabled={!verified || isSubmitting}
              >
                {t_i18n('Update')}
              </Button>
            </Box>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

const RetentionEditionFragment = createFragmentContainer(
  RetentionEditionContainer,
  {
    retentionRule: graphql`
            fragment RetentionEdition_retentionRule on RetentionRule {
                id
                name
                retention_unit
                max_retention
                filters
                scope
                active
            }
        `,
  },
);

export default RetentionEditionFragment;
