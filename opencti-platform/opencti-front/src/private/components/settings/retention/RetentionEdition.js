import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import Chip from '@material-ui/core/Chip';
import * as R from 'ramda';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters, { isUniqFilter } from '../../common/lists/Filters';
import { adaptFieldValue, truncate } from '../../../../utils/String';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
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
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  filters: {
    marginTop: 20,
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.chip,
    margin: '0 10px 10px 0',
  },
});

const retentionMutationFieldPatch = graphql`
  mutation RetentionEditionFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    retentionRuleEdit(id: $id) {
      fieldPatch(input: $input) {
        ...RetentionEdition_retentionRule
      }
    }
  }
`;

const retentionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  max_retention: Yup.number().min(1, t('This field must be >= 1')),
});

const RetentionEditionContainer = (props) => {
  const {
    t, classes, handleClose, retentionRule,
  } = props;
  const initialValues = R.pickAll(['name', 'max_retention'], retentionRule);
  const [filters, setFilters] = useState(
    JSON.parse(props.retentionRule.filters),
  );
  const onSubmit = (values, { setSubmitting }) => {
    const inputValues = R.pipe(
      R.assoc('filters', JSON.stringify(filters)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: retentionMutationFieldPatch,
      variables: {
        id: props.retentionRule.id,
        input: inputValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const handleAddFilter = (key, id, value) => {
    if (filters[key]) {
      if (filters[key].length > 0) {
        setFilters(
          R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
            filters,
          ),
        );
      } else {
        setFilters(R.assoc(key, [{ id, value }], filters));
      }
    } else {
      setFilters(R.assoc(key, [{ id, value }], filters));
    }
  };
  const handleRemoveFilter = (key) => {
    setFilters(R.dissoc(key, filters));
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
        <Typography variant="h6">{t('Update a retention policy')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={retentionValidation(t)}
          onSubmit={onSubmit}
        >
          {({ isSubmitting, submitForm }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                name="name"
                label={t('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                name="max_retention"
                label={t('Maximum retention days')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <div style={{ marginTop: 35 }}>
                <Filters
                  variant="text"
                  availableFilterKeys={[
                    'entity_type',
                    'markedBy',
                    'labelledBy',
                    'createdBy',
                    'x_opencti_score_gt',
                    'x_opencti_detection',
                    'revoked',
                    'confidence_gt',
                    'pattern_type',
                  ]}
                  currentFilters={{}}
                  handleAddFilter={handleAddFilter}
                  noDirectFilters={true}
                />
              </div>
              <div className="clearfix" />
              <div className={classes.filters}>
                {R.map((currentFilter) => {
                  const label = `${truncate(
                    t(`filter_${currentFilter[0]}`),
                    20,
                  )}`;
                  const values = (
                    <span>
                      {R.map(
                        (n) => (
                          <span key={n.value}>
                            {n.value && n.value.length > 0
                              ? truncate(n.value, 15)
                              : t('No label')}{' '}
                            {R.last(currentFilter[1]).value !== n.value && (
                              <code>OR</code>
                            )}{' '}
                          </span>
                        ),
                        currentFilter[1],
                      )}
                    </span>
                  );
                  return (
                    <span key={currentFilter[0]}>
                      <Chip
                        classes={{ root: classes.filter }}
                        label={
                          <div>
                            <strong>{label}</strong>: {values}
                          </div>
                        }
                        onDelete={() => handleRemoveFilter(currentFilter[0])}
                      />
                      {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                        <Chip
                          classes={{ root: classes.operator }}
                          label={t('AND')}
                        />
                      )}
                    </span>
                  );
                }, R.toPairs(filters))}
              </div>
              <DialogActions>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  style={{ marginTop: 20, float: 'right' }}
                >
                  {t('Update')}
                </Button>
              </DialogActions>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

RetentionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  retentionRule: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const RetentionEditionFragment = createFragmentContainer(
  RetentionEditionContainer,
  {
    retentionRule: graphql`
      fragment RetentionEdition_retentionRule on RetentionRule {
        id
        name
        max_retention
        filters
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RetentionEditionFragment);
