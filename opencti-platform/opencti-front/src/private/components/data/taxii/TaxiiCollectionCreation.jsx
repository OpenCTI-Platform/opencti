import React from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Box from '@mui/material/Box';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { emptyFilterGroup, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';

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
  title: {
    float: 'left',
  },
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
});

const TaxiiCollectionCreationMutation = graphql`
    mutation TaxiiCollectionCreationMutation($input: TaxiiCollectionAddInput!) {
        taxiiCollectionAdd(input: $input) {
            ...TaxiiLine_node
        }
    }
`;

const taxiiCollectionCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  authorized_members: Yup.array().nullable(),
  taxii_public: Yup.bool().nullable(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_taxiiCollections',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const TaxiiCollectionCreation = (props) => {
  const { t, classes } = props;
  const [filters, helpers] = useFiltersState(emptyFilterGroup);
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const authorized_members = values.authorized_members.map(({ value }) => ({
      id: value,
      access_right: 'view',
    }));
    commitMutation({
      mutation: TaxiiCollectionCreationMutation,
      variables: {
        input: { ...values, filters: jsonFilters, authorized_members },
      },
      updater: (store) => {
        const payload = store.getRootField('taxiiCollectionAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          props.paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer
      title={t('Create a TAXII collection')}
      variant={DrawerVariant.createWithPanel}
      onClose={helpers.handleClearAllFilters}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            authorized_members: [],
          }}
          validationSchema={taxiiCollectionCreationValidation(t)}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ values, setFieldValue, submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t('Description')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Alert
                icon={false}
                classes={{ root: classes.alert, message: classes.message }}
                severity="warning"
                variant="outlined"
                style={{ position: 'relative' }}
              >
                <AlertTitle>
                  {t('Make this taxii collection public and available to anyone')}
                </AlertTitle>
                <FormControlLabel
                  control={<Switch />}
                  style={{ marginLeft: 1 }}
                  name="taxii_public"
                  onChange={(_, checked) => setFieldValue('taxii_public', checked)}
                  label={t('Public collection')}
                />
                {!values.taxii_public && (
                  <ObjectMembersField
                    label={'Accessible for'}
                    style={fieldSpacingContainerStyle}
                    helpertext={t('Let the field empty to grant all authenticated users')}
                    multiple={true}
                    name="authorized_members"
                  />
                )}
              </Alert>
              <Box sx={{ paddingTop: 4,
                display: 'flex',
                gap: 1 }}
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
                  noDirectFilters={true}
                />
              </Box>
              <FilterIconButton
                filters={filters}
                helpers={helpers}
                styleNumber={2}
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
                  onClick={submitForm}
                  disabled={!isFilterGroupNotEmpty(filters) || isSubmitting}
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

TaxiiCollectionCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(TaxiiCollectionCreation);
