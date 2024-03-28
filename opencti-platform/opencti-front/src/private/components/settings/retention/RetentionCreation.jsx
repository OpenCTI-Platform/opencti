import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import InputAdornment from '@mui/material/InputAdornment';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { insertNode } from '../../../../utils/store';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
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
  title: {
    float: 'left',
  },
});

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

const OBJECT_TYPE = 'RetentionRule';

const RetentionCreation = (props) => {
  const { t, classes } = props;

  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const basicShape = {
    name: Yup.string(),
    max_retention: Yup.number().min(1, t('This field must be >= 1')),
    filters: Yup.string(),
  };
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const [filters, helpers] = useFiltersState();

  const [verified, setVerified] = useState(false);

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const finalValues = R.pipe(
      R.assoc('max_retention', Number(values.max_retention)),
    )(values);
    const jsonFilters = serializeFilterGroupForBackend(filters);
    commitMutation({
      mutation: RetentionCreationMutation,
      variables: {
        input: { ...finalValues, filters: jsonFilters },
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_retentionRules',
          props.paginationOptions,
          'retentionRuleAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const handleVerify = (values) => {
    const finalValues = R.pipe(
      R.assoc('max_retention', Number(values.max_retention)),
    )(values);
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
      title={t('Create a retention policy')}
      variant={DrawerVariant.createWithPanel}
      onClose={helpers.handleClearAllFilters}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{ name: '', max_retention: '31', filters: '' }}
          validationSchema={validator}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, values: formValues }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="max_retention"
                label={t('Maximum retention days')}
                required={(mandatoryAttributes.includes('max_retention'))}
                fullWidth={true}
                onChange={() => setVerified(false)}
                style={{ marginTop: 20 }}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <Tooltip
                        title={t(
                          'All objects matching the filters that have not been updated since this amount of days will be deleted',
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
                }}
              />
              <Box sx={{ paddingTop: 4,
                display: 'flex',
                gap: 1 }}
              >
                <Filters
                  required={(mandatoryAttributes.includes('filters'))}
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
                redirection
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={() => handleVerify(formValues)}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Verify')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={!verified || isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

RetentionCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RetentionCreation);
