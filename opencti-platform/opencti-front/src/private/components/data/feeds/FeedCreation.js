import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, AddOutlined, CancelOutlined, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import Grid from '@mui/material/Grid';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MuiTextField from '@mui/material/TextField';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import SwitchField from '../../../../components/SwitchField';
import { stixCyberObservablesLinesAttributesQuery } from '../../observations/stix_cyber_observables/StixCyberObservablesLines';
import { ignoredAttributesInFeeds } from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import Filters, { isUniqFilter } from '../../common/lists/Filters';
import { truncate } from '../../../../utils/String';

export const feedCreationAllTypesQuery = graphql`
  query FeedCreationAllTypesQuery {
    scoTypes: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    sdoTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
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
  title: {
    float: 'left',
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 5,
    display: 'flex',
  },
  formControl: {
    width: '100%',
  },
  stepType: {
    margin: 0,
    paddingRight: 20,
    width: '30%',
  },
  stepField: {
    margin: 0,
    paddingRight: 20,
    width: '30%',
  },
  stepValues: {
    paddingRight: 20,
    margin: 0,
  },
  stepCloseButton: {
    position: 'absolute',
    top: -20,
    right: -20,
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  buttonAdd: {
    width: '100%',
    height: 20,
  },
  filters: {
    marginTop: 20,
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 10px 0',
  },
});

const feedCreationMutation = graphql`
  mutation FeedCreationMutation($input: FeedAddInput!) {
    feedAdd(input: $input) {
      ...FeedLine_node
    }
  }
`;

const feedCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  separator: Yup.string().required(t('This field is required')),
  rolling_time: Yup.number().required(t('This field is required')),
  feed_types: Yup.array().required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_feeds',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const FeedCreation = (props) => {
  const { t, classes } = props;
  const [open, setOpen] = useState(false);
  const [selectedTypes, setSelectedTypes] = useState([]);
  const [filters, setFilters] = useState({});
  const [feedAttributes, setFeedAttributes] = useState({ 0: {} });

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleSelectTypes = (types) => {
    setSelectedTypes(types);
    // feed attributes must be eventually cleanup in case of types removal
    const attrValues = R.values(feedAttributes);
    // noinspection JSMismatchedCollectionQueryUpdate
    const updatedFeedAttributes = [];
    for (let index = 0; index < attrValues.length; index += 1) {
      const feedAttr = attrValues[index];
      const mappingEntries = Object.entries(feedAttr.mappings);
      const keepMappings = mappingEntries.filter(([k]) => types.includes(k));
      updatedFeedAttributes.push({
        attribute: feedAttr.attribute,
        mappings: R.fromPairs(keepMappings),
      });
    }
    setFeedAttributes({ ...updatedFeedAttributes });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const finalFeedAttributes = R.values(feedAttributes).map((n) => ({
      attribute: n.attribute,
      mappings: R.values(n.mappings),
    }));
    const finalValues = R.pipe(
      R.assoc('rolling_time', parseInt(values.rolling_time, 10)),
      R.assoc('feed_attributes', finalFeedAttributes),
      R.assoc('filters', JSON.stringify(filters)),
    )(values);
    commitMutation({
      mutation: feedCreationMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('feedAdd');
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

  const areAttributesValid = () => {
    if (Object.keys(feedAttributes).length === 0) {
      return false;
    }
    for (const n of Object.keys(feedAttributes)) {
      const feedAttribute = feedAttributes[n];
      if (
        !feedAttribute
        || !feedAttribute.attribute
        || !feedAttribute.mappings
        || R.values(feedAttribute.mappings).length !== selectedTypes.length
        || R.values(feedAttribute.mappings).filter(
          (m) => !m.attribute
            || !m.type
            || m.attribute.length === 0
            || m.type.length === 0,
        ).length > 0
      ) {
        return false;
      }
    }
    return true;
  };

  const handleAddAttribute = () => {
    const newKey = R.last(Object.keys(feedAttributes))
      ? R.last(Object.keys(feedAttributes)) + 1
      : 0;
    setFeedAttributes(R.assoc(newKey, {}, feedAttributes));
  };

  const handleRemoveAttribute = (i) => {
    setFeedAttributes(R.dissoc(i, feedAttributes));
  };

  const handleChangeField = (i, value) => {
    const newFeedAttribute = R.assoc('attribute', value, feedAttributes[i]);
    setFeedAttributes(R.assoc(i, newFeedAttribute, feedAttributes));
  };

  const handleChangeAttributeMapping = (i, type, value) => {
    const mapping = { type, attribute: value };
    const newFeedAttributeMapping = R.assoc(
      type,
      mapping,
      feedAttributes[i].mappings || {},
    );
    const newFeedAttribute = R.assoc(
      'mappings',
      newFeedAttributeMapping,
      feedAttributes[i],
    );
    setFeedAttributes(R.assoc(i, newFeedAttribute, feedAttributes));
  };

  const handleAddFilter = (key, id, value) => {
    if (filters[key] && filters[key].length > 0) {
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
  };

  const handleRemoveFilter = (key) => {
    setFilters(R.dissoc(key, filters));
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
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
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
          <Typography variant="h6">{t('Create a feed')}</Typography>
        </div>
        <div className={classes.container}>
          <QueryRenderer
            query={feedCreationAllTypesQuery}
            render={({ props: data }) => {
              if (data && data.scoTypes && data.sdoTypes) {
                let result = [];
                result = [
                  ...R.pipe(
                    R.pathOr([], ['scoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
                result = [
                  ...R.pipe(
                    R.pathOr([], ['sdoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
                const entitiesTypes = R.sortWith(
                  [R.ascend(R.prop('label'))],
                  result,
                );
                return (
                  <Formik
                    initialValues={{
                      name: '',
                      separator: ';',
                      rolling_time: 60,
                      include_header: true,
                      feed_types: [],
                    }}
                    validationSchema={feedCreationValidation(t)}
                    onSubmit={onSubmit}
                    onReset={onReset}
                  >
                    {({ submitForm, handleReset, isSubmitting }) => (
                      <Form style={{ margin: '20px 0 20px 0' }}>
                        <Field
                          component={TextField}
                          variant="standard"
                          name="name"
                          label={t('Name')}
                          fullWidth={true}
                        />
                        <Field
                          component={TextField}
                          variant="standard"
                          name="separator"
                          label={t('Separator')}
                          fullWidth={true}
                          style={{ marginTop: 20 }}
                        />
                        <Field
                          component={TextField}
                          variant="standard"
                          type="number"
                          name="rolling_time"
                          label={t('Rolling time (in minutes)')}
                          fullWidth={true}
                          style={{ marginTop: 20 }}
                        />
                        <Field
                          component={SelectField}
                          variant="standard"
                          name="feed_types"
                          onChange={(_, value) => handleSelectTypes(value)}
                          label={t('Entity types')}
                          fullWidth={true}
                          multiple={true}
                          containerstyle={{ width: '100%', marginTop: 20 }}
                        >
                          {entitiesTypes.map((type) => (
                            <MenuItem key={type.value} value={type.value}>
                              {type.label}
                            </MenuItem>
                          ))}
                        </Field>
                        <Field
                          component={SwitchField}
                          type="checkbox"
                          name="include_header"
                          label={t('Include headers in the feed')}
                          containerstyle={{ marginTop: 20 }}
                        />
                        <div style={{ marginTop: 35 }}>
                          <Filters
                            variant="text"
                            availableFilterKeys={[
                              'markedBy',
                              'labelledBy',
                              'createdBy',
                              'x_opencti_score_gt',
                              'x_opencti_detection',
                              'revoked',
                              'confidence_gt',
                              'pattern_type',
                            ]}
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
                                      {R.last(currentFilter[1]).value
                                        !== n.value && <code>OR</code>}{' '}
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
                                  onDelete={() => handleRemoveFilter(currentFilter[0])
                                  }
                                />
                                {R.last(R.toPairs(filters))[0]
                                  !== currentFilter[0] && (
                                  <Chip
                                    classes={{ root: classes.operator }}
                                    label={t('AND')}
                                  />
                                )}
                              </span>
                            );
                          }, R.toPairs(filters))}
                        </div>
                        {selectedTypes.length > 0 && (
                          <div
                            className={classes.container}
                            style={{ marginTop: 20 }}
                          >
                            {Object.keys(feedAttributes).map((i) => (
                              <div key={i} className={classes.step}>
                                <IconButton
                                  disabled={feedAttributes.length === 1}
                                  aria-label="Delete"
                                  className={classes.stepCloseButton}
                                  onClick={() => handleRemoveAttribute(i)}
                                  size="large"
                                >
                                  <CancelOutlined fontSize="small" />
                                </IconButton>
                                <Grid container={true} spacing={3}>
                                  <Grid item={true} xs="auto">
                                    <MuiTextField
                                      variant="standard"
                                      name="attribute"
                                      label={t('Column')}
                                      fullWidth={true}
                                      value={feedAttributes[i].attribute}
                                      onChange={(event) => handleChangeField(i, event.target.value)
                                      }
                                    />
                                  </Grid>
                                  {selectedTypes.map((selectedType) => (
                                    <Grid
                                      key={selectedType}
                                      item={true}
                                      xs="auto"
                                    >
                                      <FormControl
                                        className={classes.formControl}
                                      >
                                        <InputLabel variant="standard">
                                          {t(`entity_${selectedType}`)}
                                        </InputLabel>
                                        <QueryRenderer
                                          query={
                                            stixCyberObservablesLinesAttributesQuery
                                          }
                                          variables={{
                                            elementType: selectedType,
                                          }}
                                          render={({ props: resultProps }) => {
                                            if (
                                              resultProps
                                              && resultProps.schemaAttributes
                                            ) {
                                              let attributes = R.pipe(
                                                R.map((n) => n.node),
                                                R.filter(
                                                  (n) => !R.includes(
                                                    n.value,
                                                    ignoredAttributesInFeeds,
                                                  )
                                                    && !n.value.startsWith('i_'),
                                                ),
                                              )(
                                                resultProps.schemaAttributes
                                                  .edges,
                                              );
                                              if (
                                                attributes.filter(
                                                  (n) => n.value === 'hashes',
                                                ).length > 0
                                              ) {
                                                attributes = R.sortBy(
                                                  R.prop('value'),
                                                  [
                                                    ...attributes,
                                                    { value: 'hashes.MD5' },
                                                    { value: 'hashes.SHA-1' },
                                                    { value: 'hashes.SHA-256' },
                                                    { value: 'hashes.SHA-512' },
                                                  ].filter(
                                                    (n) => n.value !== 'hashes',
                                                  ),
                                                );
                                              }
                                              return (
                                                <Select
                                                  style={{ width: 150 }}
                                                  variant="standard"
                                                  value={
                                                    feedAttributes[i]
                                                      ?.mappings
                                                    && feedAttributes[i].mappings[
                                                      selectedType
                                                    ]?.attribute
                                                  }
                                                  onChange={(event) => handleChangeAttributeMapping(
                                                    i,
                                                    selectedType,
                                                    event.target.value,
                                                  )
                                                  }
                                                >
                                                  {attributes.map(
                                                    (attribute) => (
                                                      <MenuItem
                                                        key={attribute.value}
                                                        value={attribute.value}
                                                      >
                                                        {attribute.value}
                                                      </MenuItem>
                                                    ),
                                                  )}
                                                </Select>
                                              );
                                            }
                                            return <div />;
                                          }}
                                        />
                                      </FormControl>
                                    </Grid>
                                  ))}
                                </Grid>
                              </div>
                            ))}
                            <div className={classes.add}>
                              <Button
                                disabled={!areAttributesValid()}
                                variant="contained"
                                color="secondary"
                                size="small"
                                onClick={() => handleAddAttribute()}
                                classes={{ root: classes.buttonAdd }}
                              >
                                <AddOutlined fontSize="small" />
                              </Button>
                            </div>
                          </div>
                        )}
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
                            color="secondary"
                            onClick={submitForm}
                            disabled={isSubmitting || !areAttributesValid()}
                            classes={{ root: classes.button }}
                          >
                            {t('Create')}
                          </Button>
                        </div>
                      </Form>
                    )}
                  </Formik>
                );
              }
              return <div />;
            }}
          />
        </div>
      </Drawer>
    </div>
  );
};

FeedCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(FeedCreation);
