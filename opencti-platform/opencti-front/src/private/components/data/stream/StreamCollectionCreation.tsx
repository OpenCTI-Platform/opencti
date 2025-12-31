import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler, RecordProxy, RecordSourceSelectorProxy } from 'relay-runtime';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { emptyFilterGroup, serializeFilterGroupForBackend, stixFilters } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { PaginationOptions } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

interface StreamCollectionCreationProps {
  paginationOptions: PaginationOptions;
}

interface StreamCollectionCreationForm {
  authorized_members: FieldOption[];
  stream_public: boolean;
  name: string;
  description: string;
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

const StreamCollectionCreationMutation = graphql`
    mutation StreamCollectionCreationMutation($input: StreamCollectionAddInput!) {
        streamCollectionAdd(input: $input) {
            ...StreamLine_node
        }
    }
`;

const streamCollectionCreationValidation = (requiredSentence: string) => Yup.object().shape({
  name: Yup.string().required(requiredSentence),
  description: Yup.string().nullable(),
  stream_public: Yup.bool(),
  authorized_members: Yup.array().nullable(),
});

const sharedUpdater = (store: RecordSourceSelectorProxy, userId: string, paginationOptions: PaginationOptions, newEdge: RecordProxy) => {
  const userProxy = store.get(userId);
  if (userProxy) {
    const conn = ConnectionHandler.getConnection(
      userProxy,
      'Pagination_streamCollections',
      paginationOptions,
    );
    ConnectionHandler.insertEdgeBefore(conn as RecordProxy, newEdge);
  }
};

const CreateStreamCollectionControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="StreamCollection"
    {...props}
  />
);

const StreamCollectionCreation: FunctionComponent<StreamCollectionCreationProps> = ({ paginationOptions }) => {
  const [filters, helpers] = useFiltersState(emptyFilterGroup);
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const onSubmit: FormikConfig<StreamCollectionCreationForm>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const authorized_members = values.authorized_members.map(({ value }) => ({
      id: value,
      access_right: 'view',
    }));
    commitMutation({
      mutation: StreamCollectionCreationMutation,
      variables: {
        input: { ...values, filters: jsonFilters, authorized_members },
      },
      updater: (store: RecordSourceSelectorProxy) => {
        const payload = store.getRootField('streamCollectionAdd');
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
      title={t_i18n('Create a stream')}
      controlledDial={CreateStreamCollectionControlledDial}
      onClose={helpers.handleClearAllFilters}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            stream_public: false,
            authorized_members: [] as FieldOption[],
          }}
          validationSchema={streamCollectionCreationValidation(t_i18n('This field is required'))}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
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
                  {t_i18n('Make this stream public and available to anyone')}
                </AlertTitle>
                <FormControlLabel
                  control={<Switch />}
                  style={{ marginLeft: 1 }}
                  name="stream_public"
                  onChange={(_, checked) => setFieldValue('stream_public', checked)}
                  label={t_i18n('Public stream')}
                />
                {!values.stream_public && (
                  <ObjectMembersField
                    label="Accessible for"
                    style={fieldSpacingContainerStyle}
                    helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
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
                  availableFilterKeys={stixFilters}
                  helpers={helpers}
                  searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
                />
              </Box>
              <FilterIconButton
                filters={filters}
                helpers={helpers}
                styleNumber={2}
                redirection
                searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
                entityTypes={['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering']}
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
                  disabled={isSubmitting}
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

export default StreamCollectionCreation;
