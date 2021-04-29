import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import {
  assoc,
  compose,
  dissoc,
  last,
  map,
  pickAll,
  prop,
  toPairs,
  uniqBy,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 0px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  filters: {
    float: 'left',
    margin: '-8px 18px 0 -5px',
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: 'rgba(64, 193, 255, 0.2)',
    margin: '0 10px 10px 0',
  },
});

const taxiiCollectionMutationFieldPatch = graphql`
  mutation TaxiiCollectionEditionFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    taxiiCollectionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...TaxiiCollectionEdition_taxiiCollection
      }
    }
  }
`;

const taxiiCollectionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

const TaxiiCollectionEditionContainer = (props) => {
  const {
    t, classes, handleClose, taxiiCollection,
  } = props;
  const initialValues = pickAll(['name', 'description'], taxiiCollection);
  const [filters, setFilters] = useState(
    JSON.parse(props.taxiiCollection.filters),
  );
  const handleSubmitField = (name, value) => {
    taxiiCollectionValidation(props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: taxiiCollectionMutationFieldPatch,
          variables: {
            id: props.taxiiCollection.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };
  const handleAddFilter = (key, id, value) => {
    let newFilters;
    if (filters[key] && filters[key].length > 0) {
      newFilters = assoc(
        key,
        uniqBy(prop('id'), [{ id, value }, ...filters[key]]),
        filters,
      );
    } else {
      newFilters = assoc(key, [{ id, value }], filters);
    }
    const jsonFilters = JSON.stringify(newFilters);
    commitMutation({
      mutation: taxiiCollectionMutationFieldPatch,
      variables: {
        id: props.taxiiCollection.id,
        input: { key: 'filters', value: jsonFilters },
      },
      onCompleted: () => {
        setFilters(newFilters);
      },
    });
  };
  const handleRemoveFilter = (key) => {
    const newFilters = dissoc(key, filters);
    const jsonFilters = JSON.stringify(newFilters);
    const variables = {
      id: props.taxiiCollection.id,
      input: { key: 'filters', value: jsonFilters },
    };
    commitMutation({
      mutation: taxiiCollectionMutationFieldPatch,
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
        >
          <Close fontSize="small" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a TAXII collection')}
        </Typography>
        <div style={{ float: 'right', margin: '10px 0 0 0' }}>
          <Filters
            variant="text"
            availableFilterKeys={[
              'entity_type',
              'markedBy',
              'labelledBy',
              'createdBy',
              'x_opencti_score_gt',
              'x_opencti_detection',
              'confidence_gt',
            ]}
            currentFilters={[]}
            handleAddFilter={handleAddFilter}
            noDirectFilters={true}
          />
        </div>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={taxiiCollectionValidation(t)}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                name="name"
                label={t('Collection name')}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                name="description"
                label={t('Collection description')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onSubmit={handleSubmitField}
              />
              <div style={{ marginTop: 35 }}>
                <div className={classes.filters}>
                  {map((currentFilter) => {
                    const label = `${truncate(
                      t(`filter_${currentFilter[0]}`),
                      20,
                    )}`;
                    const values = (
                      <span>
                        {map(
                          (n) => (
                            <span key={n.value}>
                              {n.value && n.value.length > 0
                                ? truncate(n.value, 15)
                                : t('No label')}{' '}
                              {last(currentFilter[1]).value !== n.value && (
                                <code>OR</code>
                              )}{' '}
                            </span>
                          ),
                          currentFilter[1],
                        )}
                      </span>
                    );
                    return (
                      <span>
                        <Chip
                          key={currentFilter[0]}
                          classes={{ root: classes.filter }}
                          label={
                            <div>
                              <strong>{label}</strong>: {values}
                            </div>
                          }
                          onDelete={() => handleRemoveFilter(currentFilter[0])}
                        />
                        {last(toPairs(filters))[0] !== currentFilter[0] && (
                          <Chip
                            classes={{ root: classes.operator }}
                            label={t('AND')}
                          />
                        )}
                      </span>
                    );
                  }, toPairs(filters))}
                </div>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

TaxiiCollectionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  taxiiCollection: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const TaxiiCollectionEditionFragment = createFragmentContainer(
  TaxiiCollectionEditionContainer,
  {
    taxiiCollection: graphql`
      fragment TaxiiCollectionEdition_taxiiCollection on TaxiiCollection {
        id
        name
        description
        filters
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(TaxiiCollectionEditionFragment);
