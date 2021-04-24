import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import {
  assoc,
  compose,
  dissoc,
  last,
  map,
  prop,
  toPairs,
  uniqBy,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
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
  title: {
    float: 'left',
  },
  filters: {
    float: 'left',
    margin: '-8px 0 0 -5px',
  },
  filter: {
    marginRight: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: 'rgba(64, 193, 255, 0.2)',
    marginRight: 10,
  },
});

const TaxiiCollectionCreationMutation = graphql`
  mutation TaxiiCollectionCreationMutation($input: TaxiiCollectionAddInput!) {
    taxiiCollectionAdd(input: $input) {
      ...TaxiiLine_node
    }
  }
`;

const taxiiCollectionCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_taxiiCollections',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const TaxiiCollectionCreation = (props) => {
  const { t, classes } = props;
  const [open, setOpen] = useState(false);
  const [filters, setFilters] = useState({});

  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const jsonFilters = JSON.stringify(filters);
    commitMutation({
      mutation: TaxiiCollectionCreationMutation,
      variables: {
        input: { ...values, filters: jsonFilters },
      },
      updater: (store) => {
        const payload = store.getRootField('taxiiCollectionAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          props.paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const onReset = () => {
    handleClose();
  };

  const handleAddFilter = (key, id, value) => {
    if (filters[key] && filters[key].length > 0) {
      setFilters(
        assoc(
          key,
          uniqBy(prop('id'), [{ id, value }, ...filters[key]]),
          filters,
        ),
      );
    } else {
      setFilters(assoc(key, [{ id, value }], filters));
    }
  };
  const handleRemoveFilter = (key) => {
    setFilters(dissoc(key, filters));
  };

  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Create a TAXII collection')}
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
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              description: '',
            }}
            validationSchema={taxiiCollectionCreationValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="name"
                  label={t('Collection name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  name="description"
                  label={t('Collection description')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
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
                            onDelete={() => handleRemoveFilter(currentFilter[0])
                            }
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
                <div className="clearfix" />
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </div>
      </Drawer>
    </div>
  );
};

TaxiiCollectionCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(TaxiiCollectionCreation);
