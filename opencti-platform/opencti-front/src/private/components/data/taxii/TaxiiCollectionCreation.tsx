import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler, RecordProxy, RecordSourceSelectorProxy } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { Theme } from '../../../../components/Theme';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { emptyFilterGroup, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { PaginationOptions } from '../../../../components/list_lines';

interface TaxiiCollectionCreationProps {
  paginationOptions: PaginationOptions
}

interface TaxiiCollectionCreationForm {
  authorized_members: Option[]
  taxii_public?: boolean
  name: string
  description: string
}

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

const TaxiiCollectionCreationMutation = graphql`
    mutation TaxiiCollectionCreationMutation($input: TaxiiCollectionAddInput!) {
        taxiiCollectionAdd(input: $input) {
            ...TaxiiLine_node
        }
    }
`;

const taxiiCollectionCreationValidation = (requiredSentence: string) => Yup.object().shape({
  name: Yup.string().required(requiredSentence),
  description: Yup.string().nullable(),
  authorized_members: Yup.array().nullable(),
  taxii_public: Yup.bool().nullable(),
});

const sharedUpdater = (store: RecordSourceSelectorProxy, userId: string, paginationOptions: PaginationOptions, newEdge: RecordProxy) => {
  const userProxy = store.get(userId);
  if (userProxy) {
    const conn = ConnectionHandler.getConnection(
      userProxy,
      'Pagination_taxiiCollections',
      paginationOptions,
    );
    ConnectionHandler.insertEdgeBefore(conn as RecordProxy, newEdge);
  }
};

const TaxiiCollectionCreation: FunctionComponent<TaxiiCollectionCreationProps> = ({ paginationOptions }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [filters, helpers] = useFiltersState(emptyFilterGroup);
  const onSubmit: FormikConfig<TaxiiCollectionCreationForm>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
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
      updater: (store: RecordSourceSelectorProxy) => {
        const payload = store.getRootField('taxiiCollectionAdd');
        const newEdge = payload?.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          paginationOptions,
          newEdge as RecordProxy,
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting,
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
          validationSchema={taxiiCollectionCreationValidation(t('This field is required'))}
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
                {!values?.taxii_public && (
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

export default TaxiiCollectionCreation;
