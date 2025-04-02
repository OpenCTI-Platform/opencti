import React, { FunctionComponent, useEffect } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import AlertTitle from '@mui/material/AlertTitle';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import Box from '@mui/material/Box';
import { Option } from '@components/common/form/ReferenceField';
import { StreamCollectionEdition_streamCollection$data } from '@components/data/stream/__generated__/StreamCollectionEdition_streamCollection.graphql';
import { FormikConfig } from 'formik/dist/types';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { deserializeFilterGroupForFrontend, serializeFilterGroupForBackend, stixFilters } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { AutoCompleteOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

interface StreamCollectionCreationForm {
  restricted_members: AutoCompleteOption[] | null
  stream_public: boolean | null
  name: string | null
  description: string | null
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
  restricted_members: Yup.array().nullable(),
});

const StreamCollectionEditionContainer: FunctionComponent<{ streamCollection: StreamCollectionEdition_streamCollection$data }> = ({ streamCollection }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const initialValues = { ...streamCollection,
    restricted_members: convertAuthorizedMembers(streamCollection),
    stream_public: streamCollection.stream_public ?? null,
    name: streamCollection.name ?? '',
    description: streamCollection.description ?? '',
  };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(streamCollection.filters) ?? undefined);
  const handleSubmitField = (name: string, value: Option[] | string) => {
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
  const handleSubmitFieldOptions = (name: string, value: Option[]) => streamCollectionValidation(t_i18n('This field is required'))
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
      {() => (
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
            classes={{ root: classes.alert, message: classes.message }}
            severity="warning"
            variant="outlined"
            style={{ position: 'relative' }}
          >
            <AlertTitle>
              {t_i18n('Make this stream public and available to anyone')}
            </AlertTitle>
            <FormControlLabel
              control={<Switch defaultChecked={!!initialValues.stream_public} />}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => handleSubmitField('stream_public', checked.toString())}
              label={t_i18n('Public stream')}
            />
            {!initialValues.stream_public && (
              <ObjectMembersField
                label={'Accessible for'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
                name="restricted_members"
              />
            )}
          </Alert>
          <Box sx={{
            paddingTop: 4,
            display: 'flex',
            gap: 1,
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
            styleNumber={2}
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
