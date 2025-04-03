import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { AddOutlined, CancelOutlined } from '@mui/icons-material';
import * as Yup from 'yup';
import { createFragmentContainer, graphql } from 'react-relay';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import Grid from '@mui/material/Grid';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MuiTextField from '@mui/material/TextField';
import InputAdornment from '@mui/material/InputAdornment';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Box from '@mui/material/Box';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import SwitchField from '../../../../components/fields/SwitchField';
import { stixCyberObservablesLinesAttributesQuery } from '../../observations/stix_cyber_observables/StixCyberObservablesLines';
import Filters from '../../common/lists/Filters';
import { feedCreationAllTypesQuery } from './FeedCreation';
import {
  cleanFilters,
  deserializeFilterGroupForFrontend,
  serializeFilterGroupForBackend,
  useAvailableFilterKeysForEntityTypes,
  useFetchFilterKeysSchema,
} from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { isNotEmptyField } from '../../../../utils/utils';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useAttributes from '../../../../utils/hooks/useAttributes';

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
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 4,
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
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
});

const feedEditionMutation = graphql`
  mutation FeedEditionMutation($id: ID!, $input: FeedAddInput!) {
    feedEdit(id: $id, input: $input) {
      ...FeedLine_node
      ...FeedEdition_feed
    }
  }
`;

const feedValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  separator: Yup.string().required(t('This field is required')),
  feed_date_attribute: Yup.string().required(t('This field is required')),
  rolling_time: Yup.number().required(t('This field is required')),
  feed_types: Yup.array().min(1, t('Minimum one entity type')).required(t('This field is required')),
  feed_public: Yup.bool().nullable(),
  authorized_members: Yup.array().nullable(),
});

const FeedEditionContainer = (props) => {
  const { t, classes, feed, handleClose, open } = props;
  const { ignoredAttributesInFeeds } = useAttributes();
  const [selectedTypes, setSelectedTypes] = useState(feed.feed_types);
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(feed.filters));
  const [feedAttributes, setFeedAttributes] = useState({
    ...feed.feed_attributes.map((n) => R.assoc('mappings', R.indexBy(R.prop('type'), n.mappings), n)),
  });

  const completeFilterKeysMap = useFetchFilterKeysSchema();
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(selectedTypes).filter((k) => k !== 'entity_type');

  const handleSelectTypes = (types) => {
    setSelectedTypes(types);
    cleanFilters(filters, helpers, types, completeFilterKeysMap);
    // feed attributes must be eventually cleanup in case of types removal
    const attrValues = R.values(feedAttributes);
    // noinspection JSMismatchedCollectionQueryUpdate
    const updatedFeedAttributes = [];
    for (let index = 0; index < attrValues.length; index += 1) {
      const feedAttr = attrValues[index];
      const mappingEntries = isNotEmptyField(feedAttr)
        ? Object.entries(feedAttr.mappings)
        : [];
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
      R.assoc('filters', serializeFilterGroupForBackend(filters)),
      R.assoc(
        'authorized_members',
        values.authorized_members.map(({ value }) => ({
          id: value,
          access_right: 'view',
        })),
      ),
    )(values);
    commitMutation({
      mutation: feedEditionMutation,
      variables: {
        id: feed.id,
        input: finalValues,
      },
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
    if (
      selectedTypes.length === 0
            || Object.keys(feedAttributes).length === 0
    ) {
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
    const newKey = R.last(Object.keys(feedAttributes)) + 1;
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

  const initialValues = {
    name: feed.name,
    description: feed.description,
    separator: feed.separator,
    rolling_time: feed.rolling_time,
    feed_date_attribute: feed.feed_date_attribute ?? 'created_at',
    include_header: feed.include_header,
    feed_types: feed.feed_types,
    feed_public: feed.feed_public,
    authorized_members: convertAuthorizedMembers(feed),
  };

  return (
    <Drawer
      title={t('Update a feed')}
      open={open}
      onClose={handleClose}
    >
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
                initialValues={initialValues}
                enableReinitialize={true}
                validationSchema={feedValidation(t)}
                onSubmit={onSubmit}
                onReset={onReset}
              >
                {({ values, submitForm, handleReset, isSubmitting }) => (
                  <Form>
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
                      name="description"
                      label={t('Description')}
                      fullWidth={true}
                      style={{ marginTop: 20 }}
                    />
                    <Alert
                      icon={false}
                      classes={{ root: classes.alert, message: classes.message }}
                      severity="warning"
                      variant="outlined"
                      style={{ position: 'relative' }}
                    >
                      <AlertTitle>
                        {t('Make this feed public and available to anyone')}
                      </AlertTitle>
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="feed_public"
                        containerstyle={{ marginLeft: 2, marginTop: 20 }}
                        label={t('Public feed')}
                      />
                      {!values.feed_public && (
                        <ObjectMembersField
                          label={'Accessible for'}
                          style={fieldSpacingContainerStyle}
                          multiple={true}
                          helpertext={t('Leave the field empty to grant all authenticated users')}
                          name="authorized_members"
                        />
                      )}
                    </Alert>
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
                      slotProps={{
                        input: {
                          endAdornment: (
                            <InputAdornment position="end">
                              <Tooltip
                                title={t(
                                  'Return all objects matching the filters that have been updated since this amount of minutes',
                                )}
                              >
                                <InformationOutline
                                  fontSize="small"
                                  color="primary"
                                  style={{ cursor: 'default' }}
                                />
                              </Tooltip>
                            </InputAdornment>
                          ),
                        },
                      }}
                    />
                    <Field
                      component={SelectField}
                      variant="standard"
                      name="feed_date_attribute"
                      label={t('Base attribute')}
                      fullWidth={true}
                      multiple={false}
                      containerstyle={{ width: '100%', marginTop: 20 }}
                    ><MenuItem key={'created_at'} value={'created_at'}>{t('Creation date')}</MenuItem>
                      <MenuItem key={'updated_at'} value={'updated_at'}>{t('Update date')}</MenuItem>
                    </Field>
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
                    <Box sx={{ paddingTop: 4,
                      display: 'flex',
                      gap: 1 }}
                    >
                      <Filters
                        availableFilterKeys={availableFilterKeys}
                        helpers={helpers}
                        searchContext={{ entityTypes: selectedTypes }}
                      />
                    </Box>
                    <FilterIconButton
                      filters={filters}
                      helpers={helpers}
                      styleNumber={2}
                      redirection
                      searchContext={{ entityTypes: selectedTypes }}
                    />
                    {selectedTypes.length > 0 && (
                      <div className={classes.container} style={{ marginTop: 20 }}>
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
                              <Grid item xs="auto">
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
                                  item
                                  xs="auto"
                                >
                                  <FormControl
                                    className={classes.formControl}
                                  >
                                    <InputLabel>
                                      {t(`entity_${selectedType}`)}
                                    </InputLabel>
                                    <QueryRenderer
                                      query={
                                        stixCyberObservablesLinesAttributesQuery
                                      }
                                      variables={{
                                        elementType: [selectedType],
                                      }}
                                      render={({ props: resultProps }) => {
                                        if (
                                          resultProps
                                          && resultProps.schemaAttributeNames
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
                                            resultProps.schemaAttributeNames.edges,
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
                                              value={
                                                feedAttributes[i]?.mappings
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
                                              {attributes.map((attribute) => (
                                                <MenuItem
                                                  key={attribute.value}
                                                  value={attribute.value}
                                                >
                                                  {attribute.value}
                                                </MenuItem>
                                              ))}
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
                            disabled={selectedTypes.length === 0}
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
                        {t('Update')}
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
    </Drawer>
  );
};

FeedEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  feed: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const FeedEditionFragment = createFragmentContainer(FeedEditionContainer, {
  feed: graphql`
    fragment FeedEdition_feed on Feed {
      id
      name
      description
      filters
      rolling_time
      include_header
      feed_types
      feed_date_attribute
      separator
      feed_attributes {
        attribute
        mappings {
          type
          attribute
        }
      }
      feed_public
      authorized_members {
        id
        member_id
        name
      }
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(FeedEditionFragment);
