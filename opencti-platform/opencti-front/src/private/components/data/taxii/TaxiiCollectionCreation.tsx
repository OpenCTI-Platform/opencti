import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
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
import type { Theme } from '../../../../components/Theme';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { useAvailableFilterKeysForEntityTypes, emptyFilterGroup, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

interface TaxiiCollectionCreationProps {
  paginationOptions: PaginationOptions;
}

interface TaxiiCollectionCreationForm {
  authorized_members: FieldOption[];
  description: string;
  include_inferences?: boolean;
  name: string;
  taxii_public?: boolean;
  score_to_confidence?: boolean;
}

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  include_inferences: Yup.bool().nullable(),
  score_to_confidence: Yup.bool().nullable(),
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

const CreateTaxiiCollectionControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="TaxiiCollection"
    {...props}
  />
);

const TaxiiCollectionCreation: FunctionComponent<TaxiiCollectionCreationProps> = ({ paginationOptions }) => {
  const { t_i18n } = useFormatter();
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
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object', 'stix-core-relationship']);
  return (
    <Drawer
      title={t_i18n('Create a TAXII collection')}
      controlledDial={CreateTaxiiCollectionControlledDial}
      onClose={helpers.handleClearAllFilters}
    >
      {({ onClose }) => (
        <Formik<TaxiiCollectionCreationForm>
          initialValues={{
            name: '',
            description: '',
            authorized_members: [],
            taxii_public: false,
            include_inferences: true,
            score_to_confidence: false,
          }}
          validationSchema={taxiiCollectionCreationValidation(t_i18n('This field is required'))}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ values, setFieldValue, submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
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
                  {t_i18n('Make this TAXII collection public and available to anyone')}
                </AlertTitle>
                <FormControlLabel
                  control={<Switch />}
                  style={{ marginLeft: 1 }}
                  name="taxii_public"
                  onChange={(_, checked) => setFieldValue('taxii_public', checked)}
                  label={t_i18n('Public collection')}
                />
                {!values.taxii_public && (
                  <ObjectMembersField
                    label="Accessible for"
                    style={fieldSpacingContainerStyle}
                    helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
                    multiple={true}
                    name="authorized_members"
                  />
                )}
              </Alert>
              <Box sx={{ display: 'flex', alignItems: 'center', marginTop: '20px' }}>
                <FormControlLabel
                  control={<Switch />}
                  style={{ marginLeft: 1 }}
                  checked={values.include_inferences}
                  name="include_inferences"
                  onChange={(_, checked) => setFieldValue('include_inferences', checked)}
                  label={t_i18n('Include inferences')}
                />
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', marginTop: '20px' }}>
                <FormControlLabel
                  control={<Switch />}
                  style={{ marginLeft: 1 }}
                  checked={values.score_to_confidence}
                  name="score_to_confidence"
                  onChange={(_, checked) => setFieldValue('score_to_confidence', checked)}
                  label={t_i18n('Copy OpenCTI scores to confidence level for indicators')}
                />
              </Box>
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
              <div className={classes.buttons}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={!isFilterGroupNotEmpty(filters) || isSubmitting}
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

export default TaxiiCollectionCreation;
