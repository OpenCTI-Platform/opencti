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
import { deserializeFilterGroupForFrontend, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';

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
  authorized_members: Option[]
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
  authorized_members: Yup.array().nullable(),
});

const StreamCollectionEditionContainer: FunctionComponent<{ streamCollection: StreamCollectionEdition_streamCollection$data }> = ({ streamCollection }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const initialValues = { ...streamCollection, authorized_members: convertAuthorizedMembers(streamCollection) };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(streamCollection.filters) ?? undefined);
  const handleSubmitField = (name: string, value: Option[] | string) => {
    streamCollectionValidation(t('This field is required'))
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
  const handleSubmitFieldOptions = (name: string, value: Option[]) => streamCollectionValidation(t('This field is required'))
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
    <Formik
      onSubmit={onSubmit}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={streamCollectionValidation(t('This field is required'))}
    >
      {() => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t('Description')}
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
              {t('Make this stream public and available to anyone')}
            </AlertTitle>
            <FormControlLabel
              control={<Switch defaultChecked={!!initialValues.stream_public} />}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => handleSubmitField('stream_public', checked.toString())}
              label={t('Public stream')}
            />
            {!initialValues.stream_public && (
              <ObjectMembersField
                label={'Accessible for'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                helpertext={t('Let the field empty to grant all authenticated users')}
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
                'revoked',
                'confidence',
                'indicator_types',
                'pattern_type',
                'x_opencti_main_observable_type',
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
            styleNumber={2}
            helpers={helpers}
            redirection
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
                    name
                }
            }
        `,
  },
);

export default StreamCollectionEditionFragment;
