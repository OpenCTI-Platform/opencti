import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import { difference, head, map, pathOr, pipe } from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import GroupField from '../../common/form/GroupField';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';

const styles = (theme) => ({
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
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

const streamCollectionMutationFieldPatch = graphql`
  mutation StreamCollectionEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
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
});

const groupMutationRelationAdd = graphql`
  mutation StreamCollectionEditionGroupAddMutation($id: ID!, $groupId: ID!) {
    streamCollectionEdit(id: $id) {
      addGroup(id: $groupId) {
        ...StreamCollectionEdition_streamCollection
      }
    }
  }
`;

const groupMutationRelationDelete = graphql`
  mutation StreamCollectionEditionGroupDeleteMutation($id: ID!, $groupId: ID!) {
    streamCollectionEdit(id: $id) {
      deleteGroup(id: $groupId) {
        ...StreamCollectionEdition_streamCollection
      }
    }
  }
`;

const StreamCollectionEditionContainer = (props) => {
  const { t, classes, handleClose, streamCollection } = props;
  const groups = pipe(
    pathOr([], ['groups']),
    map((n) => ({
      label: n.name,
      value: n.id,
    })),
  )(streamCollection);
  const initialValues = R.pickAll(['name', 'description'], streamCollection);
  initialValues.groups = groups;
  const [filters, setFilters] = useState(
    JSON.parse(props.streamCollection.filters),
  );
  const handleSubmitField = (name, value) => {
    streamCollectionValidation(props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: streamCollectionMutationFieldPatch,
          variables: {
            id: props.streamCollection.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };
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
        id: props.streamCollection.id,
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
      id: props.streamCollection.id,
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
  const handleChangeGroups = (name, values) => {
    const currentGroups = pipe(
      pathOr([], ['groups']),
      map((n) => ({
        label: n.name,
        value: n.id,
      })),
    )(streamCollection);

    const added = difference(values, currentGroups);
    const removed = difference(currentGroups, values);

    if (added.length > 0) {
      commitMutation({
        mutation: groupMutationRelationAdd,
        variables: {
          id: streamCollection.id,
          groupId: head(added).value,
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: groupMutationRelationDelete,
        variables: {
          id: streamCollection.id,
          groupId: head(removed).value,
        },
      });
    }
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
              <GroupField
                name="groups"
                helpertext={t('Let the field empty to grant all users')}
                style={{ marginTop: 20, width: '100%' }}
                onChange={handleChangeGroups}
              />
              <div style={{ marginTop: 35 }}>
                <Filters
                  variant="text"
                  availableFilterKeys={[
                    'entity_type',
                    'markedBy',
                    'labelledBy',
                    'createdBy',
                    'x_opencti_score',
                    'x_opencti_detection',
                    'x_opencti_workflow_id',
                    'revoked',
                    'confidence',
                    'indicator_types',
                    'pattern_type',
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
              />
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

StreamCollectionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  streamCollection: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
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
        groups {
          id
          name
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StreamCollectionEditionFragment);
