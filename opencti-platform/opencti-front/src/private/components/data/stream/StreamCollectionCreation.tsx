import { Field, Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { FormikConfig } from 'formik/dist/types';
import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import FormButtonContainer from '@common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle, FieldOption } from '../../../../utils/field';
import { emptyFilterGroup, serializeFilterGroupForBackend, stixFilters } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { StreamCollectionCreationMutation } from './__generated__/StreamCollectionCreationMutation.graphql';
import { StreamLinesPaginationQuery$variables } from '../__generated__/StreamLinesPaginationQuery.graphql';

export const streamCollectionCreationMutation = graphql`
  mutation StreamCollectionCreationMutation($input: StreamCollectionAddInput!) {
    streamCollectionAdd(input: $input) {
      id
      name
      description
      ...StreamLine_node
    }
  }
`;

interface StreamCollectionFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  filters: FilterGroup;
  helpers: ReturnType<typeof useFiltersState>[1];
}

export interface StreamCollectionCreationFormValues {
  name: string;
  description: string;
  stream_public: boolean;
  authorized_members: FieldOption[];
}

const StreamCollectionCreationForm = ({
  updater,
  onReset,
  onCompleted,
  filters,
  helpers,
}: StreamCollectionFormProps) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation<StreamCollectionCreationMutation>(streamCollectionCreationMutation);

  const onSubmit: FormikConfig<StreamCollectionCreationFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const authorized_members = values.authorized_members.map(({ value }) => ({
      id: value,
      access_right: 'view',
    }));

    commit({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          stream_public: values.stream_public,
          authorized_members,
          filters: jsonFilters,
        },
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'streamCollectionAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    stream_public: Yup.bool(),
    authorized_members: Yup.array().nullable(),
  });

  return (
    <Formik<StreamCollectionCreationFormValues>
      initialValues={{
        name: '',
        description: '',
        stream_public: false,
        authorized_members: [],
      }}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth
            />
            <Field
              component={TextField}
              variant="standard"
              name="description"
              label={t_i18n('Description')}
              fullWidth
            />
            <Alert
              icon={false}
              severity="warning"
              variant="outlined"
              sx={{ width: '100%', position: 'relative' }}
            >
              <AlertTitle>
                {t_i18n('Make this stream public and available to anyone')}
              </AlertTitle>
              <FormControlLabel
                control={(
                  <Switch
                    checked={values.stream_public}
                    onChange={(_, checked) => setFieldValue('stream_public', checked)}
                  />
                )}
                label={t_i18n('Public stream')}
              />
              {!values.stream_public && (
                <ObjectMembersField
                  label="Accessible for"
                  style={fieldSpacingContainerStyle}
                  helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
                  multiple
                  name="authorized_members"
                />
              )}
            </Alert>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Filters
                availableFilterKeys={stixFilters}
                helpers={helpers}
                searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
              />
            </Box>
            <FilterIconButton
              filters={filters}
              helpers={helpers}
              redirection
              searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
            />
          </div>
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

const StreamCollectionCreation = ({ paginationOptions }: { paginationOptions: StreamLinesPaginationQuery$variables }) => {
  const { t_i18n } = useFormatter();
  const [filters, helpers] = useFiltersState(emptyFilterGroup);

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_streamCollections',
    paginationOptions,
    'streamCollectionAdd',
  );

  const CreateStreamControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="StreamCollection" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a stream')}
      controlledDial={CreateStreamControlledDial}
      onClose={helpers.handleClearAllFilters}
    >
      {({ onClose }) => (
        <StreamCollectionCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          filters={filters}
          helpers={helpers}
        />
      )}
    </Drawer>
  );
};

export default StreamCollectionCreation;
