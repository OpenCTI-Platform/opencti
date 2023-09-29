import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import AlertTitle from '@mui/material/AlertTitle';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers } from '../../../../utils/edition';

const useStyles = makeStyles((theme) => ({
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
  container: {
    padding: '10px 20px 20px 20px',
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

export const streamCollectionMutationFieldPatch = graphql`
  mutation StreamCollectionEditionFieldPatchMutation($id: ID!$input: [EditInput]!) {
    streamCollectionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StreamCollectionEdition_streamCollection
      }
    }
  }
`;

const streamCollectionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  stream_public: Yup.bool().nullable(),
  authorized_members: Yup.array().nullable(),
});

const StreamCollectionEditionContainer = ({ handleClose, streamCollection }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const initialValues = { ...streamCollection, authorized_members: convertAuthorizedMembers(streamCollection) };
  const [filters, setFilters] = useState(
    JSON.parse(streamCollection.filters),
  );
  const handleSubmitField = (name, value) => {
    streamCollectionValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: streamCollectionMutationFieldPatch,
          variables: {
            id: streamCollection.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };
  const handleSubmitFieldOptions = (name, value) => streamCollectionValidation(t)
    .validateAt(name, { [name]: value })
    .then(() => {
      commitMutation({
        mutation: streamCollectionMutationFieldPatch,
        variables: {
          id: streamCollection.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
      });
    })
    .catch(() => false);
  const handleAddFilter = (key, id, value) => {
    let newFilters;
    if (filters[key] && filters[key].length > 0) {
      newFilters = {
        ...filters,
        [key]: isUniqFilter(key)
          ? [{ id, value }]
          : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
      };
    } else {
      newFilters = { ...filters, [key]: [{ id, value }] };
    }
    const jsonFilters = JSON.stringify(newFilters);
    commitMutation({
      mutation: streamCollectionMutationFieldPatch,
      variables: {
        id: streamCollection.id,
        input: { key: 'filters', value: jsonFilters },
      },
      onCompleted: () => {
        setFilters(newFilters);
      },
    });
  };
  const handleRemoveFilter = (key) => {
    const newFilters = R.dissoc(key, filters);
    const jsonFilters = JSON.stringify(newFilters);
    const variables = {
      id: streamCollection.id,
      input: { key: 'filters', value: jsonFilters },
    };
    commitMutation({
      mutation: streamCollectionMutationFieldPatch,
      variables,
      onCompleted: () => {
        setFilters(newFilters);
      },
    });
  };
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{t('Update a live stream')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={streamCollectionValidation(t)}
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
                  control={<Switch defaultChecked={initialValues.stream_public} />}
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
              <div style={{ marginTop: 35 }}>
                <Filters
                  variant="text"
                  availableFilterKeys={[
                    'entity_type',
                    'x_opencti_workflow_id',
                    'assigneeTo',
                    'objectContains',
                    'markedBy',
                    'labelledBy',
                    'creator',
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
                  handleAddFilter={handleAddFilter}
                  noDirectFilters={true}
                />
              </div>
              <div className="clearfix" />
              <FilterIconButton
                filters={filters}
                classNameNumber={2}
                styleNumber={2}
                handleRemoveFilter={handleRemoveFilter}
                redirection
              />
            </Form>
          )}
        </Formik>
      </div>
    </div>
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
