import React, { FunctionComponent, useEffect } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import AlertTitle from '@mui/material/AlertTitle';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import { StreamCollectionEdition_streamCollection$data } from '@components/data/stream/__generated__/StreamCollectionEdition_streamCollection.graphql';
import { FormikConfig } from 'formik/dist/types';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { deserializeFilterGroupForFrontend, serializeFilterGroupForBackend, stixFilters } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatorField from '../../common/form/CreatorField';
import { convertAuthorizedMembers, convertUser } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { useTheme } from '@mui/material/styles';

interface StreamCollectionCreationForm {
  restricted_members: FieldOption[] | null;
  stream_public: boolean | null;
  name: string | null;
  description: string | null;
  stream_public_user_id?: FieldOption | string | null;
}

export const streamCollectionMutationFieldPatch = graphql`
    mutation StreamCollectionEditionFieldPatchMutation($id: ID!$input: [EditInput]!) {
        streamCollectionEdit(id: $id) {
            fieldPatch(input: $input) {
                ...StreamCollectionEdition_streamCollection
            }
        }
    }
`;

const streamCollectionValidation = (requiredSentence: string) => Yup.object().shape({
  name: Yup.string().required(requiredSentence),
  description: Yup.string().nullable(),
  stream_public: Yup.bool().nullable(),
  stream_public_user_id: Yup.mixed().nullable(),
  restricted_members: Yup.array().nullable(),
});

const StreamCollectionEditionContainer: FunctionComponent<{ streamCollection: StreamCollectionEdition_streamCollection$data }> = ({ streamCollection }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const isGrantedToSetAccesses = useGranted([SETTINGS_SETACCESSES]);
  const initialValues = { ...streamCollection,
    restricted_members: convertAuthorizedMembers(streamCollection),
    stream_public: streamCollection.stream_public ?? null,
    name: streamCollection.name ?? '',
    description: streamCollection.description ?? '',
    stream_public_user_id: convertUser(streamCollection, 'stream_public_user'),
  };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(streamCollection.filters) ?? undefined);
  const handleSubmitField = (name: string, value: FieldOption[] | string) => {
    streamCollectionValidation(t_i18n('This field is required'))
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: streamCollectionMutationFieldPatch,
          variables: {
            id: streamCollection.id,
            input: { key: name, value: value || '' },
          },
          setSubmitting: undefined,
          onCompleted: undefined,
          onError: undefined,
          optimisticResponse: undefined,
          optimisticUpdater: undefined,
          updater: undefined,
        });
      })
      .catch(() => false);
  };
  const handleSubmitFieldOptions = (name: string, value: FieldOption[]) => streamCollectionValidation(t_i18n('This field is required'))
    .validateAt(name, { [name]: value })
    .then(() => {
      commitMutation({
        mutation: streamCollectionMutationFieldPatch,
        variables: {
          id: streamCollection.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
        setSubmitting: undefined,
        onCompleted: undefined,
        onError: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        updater: undefined,
      });
    })
    .catch(() => false);

  useEffect(() => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const variables = {
      id: streamCollection.id,
      input: { key: 'filters', value: jsonFilters },
    };
    commitMutation({
      mutation: streamCollectionMutationFieldPatch,
      variables,
      setSubmitting: undefined,
      onCompleted: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      updater: undefined,
    });
  }, [filters]);
  const onSubmit: FormikConfig<StreamCollectionCreationForm>['onSubmit'] = () => {};

  return (
    <Formik<StreamCollectionCreationForm>
      onSubmit={onSubmit}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={streamCollectionValidation(t_i18n('This field is required'))}
    >
      {({ values, setFieldValue }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
          <Alert
            icon={false}
            sx={{
              width: '100%',
              marginTop: 3,
              '& .MuiAlert-message': {
                width: '100%',
                overflow: 'hidden',
              },
            }}
            severity="warning"
            variant="outlined"
            style={{ position: 'relative' }}
          >
            <AlertTitle>
              {t_i18n('Make this stream public and available to anyone')}
            </AlertTitle>
            <FormControlLabel
              control={<Switch checked={!!values.stream_public} disabled={!isGrantedToSetAccesses} />}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => {
                setFieldValue('stream_public', checked);
                if (!checked) {
                  handleSubmitField('stream_public', 'false');
                }
              }}
              label={t_i18n('Public stream')}
            />
            {!values.stream_public && (
              <ObjectMembersField
                label="Accessible for"
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
                name="restricted_members"
              />
            )}
            {values.stream_public && (
              <CreatorField
                name="stream_public_user_id"
                label={t_i18n('Share data corresponding to permissions associated with this user')}
                containerStyle={fieldSpacingContainerStyle}
                disabled={!isGrantedToSetAccesses}
                onChange={(_, value) => {
                  const userId = (value as FieldOption)?.value ?? '';
                  if (!streamCollection.stream_public) {
                    commitMutation({
                      mutation: streamCollectionMutationFieldPatch,
                      variables: {
                        id: streamCollection.id,
                        input: [
                          { key: 'stream_public_user_id', value: userId },
                          { key: 'stream_public', value: 'true' },
                        ],
                      },
                      setSubmitting: undefined,
                      onCompleted: undefined,
                      onError: undefined,
                      optimisticResponse: undefined,
                      optimisticUpdater: undefined,
                      updater: undefined,
                    });
                  } else {
                    handleSubmitField('stream_public_user_id', userId);
                  }
                }}
              />
            )}
          </Alert>
          <Box sx={{
            marginTop: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(1),
            marginBottom: theme.spacing(1),
          }}
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
            redirection={true}
            searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
            entityTypes={['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering']}
          />
        </Form>
      )}
    </Formik>
  );
};

const StreamCollectionEditionFragment = createFragmentContainer(
  StreamCollectionEditionContainer,
  {
    streamCollection: graphql`
            fragment StreamCollectionEdition_streamCollection on StreamCollection {
                id
                name
                description
                filters
                stream_live
                stream_public
                stream_public_user {
                    id
                    entity_type
                    name
                }
                authorized_members {
                    id
                    member_id
                    name
                }
            }
        `,
  },
);

export default StreamCollectionEditionFragment;
