import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import * as R from 'ramda';
import InputAdornment from '@mui/material/InputAdornment';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Button from '@common/button/Button';
import Box from '@mui/material/Box';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { adaptFieldValue } from '../../../../utils/String';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import Drawer from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import SelectField from '../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 0px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  title: {
    float: 'left',
  },
});

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

const retentionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  max_retention: Yup.number().min(1, t('This field must be >= 1')),
});

const RetentionEditionContainer = (props) => {
  const { t, classes, open, handleClose, retentionRule } = props;
  const initialValues = R.pickAll(['name', 'max_retention', 'retention_unit'], retentionRule);
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(props.retentionRule?.filters ?? undefined));
  const [verified, setVerified] = useState(true);
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
          t(`Retention policy will delete ${data.retentionRuleCheck} elements`),
        );
      },
      onError: () => {
        setVerified(false);
      },
    });
  };
  return (
    <Drawer
      title={t('Update a retention policy')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={retentionValidation(t)}
        onSubmit={onSubmit}
      >
        {({ isSubmitting, submitForm, values }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
            />
            <Field
              component={SelectField}
              variant="standard"
              name="retention_unit"
              label={t('Unit')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
            >
              <MenuItem value="minutes">{t('minutes')}</MenuItem>
              <MenuItem value="hours">{t('hours')}</MenuItem>
              <MenuItem value="days">{t('days')}</MenuItem>
            </Field>
            <Field
              component={TextField}
              variant="standard"
              name="max_retention"
              label={t('Maximum retention')}
              onChange={() => setVerified(false)}
              fullWidth={true}
              style={{ marginTop: 20 }}
              slotProps={{
                input: {
                  endAdornment: (
                    <InputAdornment position="end">
                      <Tooltip
                        title={t(
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
            {retentionRule.scope === 'knowledge'
              && (
                <>
                  <Box
                    sx={{
                      paddingTop: 4,
                      display: 'flex',
                      gap: 1,
                    }}
                  >
                    <Filters
                      availableFilterKeys={[
                        'entity_type',
                        'workflow_id',
                        'objectAssignee',
                        'objects',
                        'objectMarking',
                        'objectLabel',
                        'creator_id',
                        'createdBy',
                        'priority',
                        'severity',
                        'x_opencti_score',
                        'x_opencti_detection',
                        'x_opencti_main_observable_type',
                        'revoked',
                        'confidence',
                        'indicator_types',
                        'pattern_type',
                        'fromId',
                        'toId',
                        'fromTypes',
                        'toTypes',
                      ]}
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
              )
            }
            <div className={classes.buttons}>
              <Button
                color="secondary"
                onClick={() => handleVerify(values)}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Verify')}
              </Button>
              <Button
                color="primary"
                onClick={submitForm}
                classes={{ root: classes.button }}
                disabled={!verified || isSubmitting}
              >
                {t('Update')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

RetentionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  retentionRule: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
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
            }
        `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RetentionEditionFragment);
