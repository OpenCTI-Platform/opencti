import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { AddOutlined, CancelOutlined } from '@mui/icons-material';
import * as Yup from 'yup';
import { createFragmentContainer, graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
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
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { FeedCreationAllTypesQuery$data } from '@components/data/feeds/__generated__/FeedCreationAllTypesQuery.graphql';
import { FeedAttributeMappingInput } from '@components/data/feeds/__generated__/FeedEditionMutation.graphql';
import { StixCyberObservablesLinesAttributesQuery$data } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservablesLinesAttributesQuery.graphql';
import { Option } from '@components/common/form/ReferenceField';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import inject18n, { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import SwitchField from '../../../../components/fields/SwitchField';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { stixCyberObservablesLinesAttributesQuery } from '../../observations/stix_cyber_observables/StixCyberObservablesLines';
import Filters from '../../common/lists/Filters';
import {
  cleanFilters,
  deserializeFilterGroupForFrontend,
  emptyFilterGroup,
  serializeFilterGroupForBackend,
  useAvailableFilterKeysForEntityTypes,
  useFetchFilterKeysSchema,
} from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { isNotEmptyField } from '../../../../utils/utils';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { PaginationOptions } from '../../../../components/list_lines';
import { FilterDefinition } from '../../../../utils/hooks/useAuth';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useHelper from '../../../../utils/hooks/useHelper';

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
// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme: Theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  container: {
    padding: '10px 20px 20px 20px',
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
  stepCloseButton: {
    position: 'absolute',
    top: -20,
    right: -20,
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
}));

const feedCreationMutation = graphql`
    mutation FeedCreationMutation($input: FeedAddInput!) {
        feedAdd(input: $input) {
            ...FeedLine_node
        }
    }
`;

interface FeedAddInput {
  name: string;
  description: string;
  filters: string;
  separator: string;
  feed_date_attribute: string;
  rolling_time: number;
  include_header: boolean;
  feed_types: string[];
  feed_public: boolean;
  feed_attributes: FeedAttributeMappingInput[];
  authorized_members: Option[];
}

interface FeedCreationFormProps {
  paginationOptions: PaginationOptions;
  open: boolean;
  isDuplicated: boolean;
  onDrawerClose: () => void;
  feed: FeedAddInput | undefined;
}

const feedCreationValidation = (t_i18n: (s: string) => string) => Yup.object().shape({
  name: Yup.string().required(t_i18n('This field is required')),
  separator: Yup.string().required(t_i18n('This field is required')),
  rolling_time: Yup.number().required(t_i18n('This field is required')),
  feed_types: Yup.array().min(1, t_i18n('Minimum one entity type')).required(t_i18n('This field is required')),
  feed_public: Yup.bool().nullable(),
  authorized_members: Yup.array().nullable(),
});

const CreateFeedControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType='Feed'
    {...props}
  />
);

const FeedCreation: FunctionComponent<FeedCreationFormProps> = (props) => {
  const { onDrawerClose, open, paginationOptions, isDuplicated, feed } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [selectedTypes, setSelectedTypes] = useState(feed?.feed_types ?? []);
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(feed?.filters) ?? emptyFilterGroup);

  const completeFilterKeysMap: Map<string, Map<string, FilterDefinition>> = useFetchFilterKeysSchema();
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(selectedTypes).filter((k) => k !== 'entity_type');

  const feedAttributesInitialState = feed && feed.feed_attributes
    ? feed.feed_attributes.map((n) => ({
      ...n,
      mappings: R.indexBy(R.prop('type'), n.mappings),
    }))
    : { 0: {} };

  // TODO: typing this state properly implies deep refactoring
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [feedAttributes, setFeedAttributes] = useState<{ [key: string]: any }>(feedAttributesInitialState);
  const { ignoredAttributesInFeeds } = useAttributes();

  const onHandleClose = () => {
    setSelectedTypes([]);
    helpers.handleClearAllFilters();
    setFeedAttributes({ 0: {} });
    if (isDuplicated) {
      onDrawerClose();
    }
  };

  const handleSelectTypes = (types: string[]) => {
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
  const [commit] = useApiMutation(feedCreationMutation);

  const onSubmit: FormikConfig<FeedAddInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const finalFeedAttributes = R.values(feedAttributes).map((n) => ({
      attribute: n.attribute,
      mappings: R.values(n.mappings),
    }));
    const finalValues = R.pipe(
      R.assoc('rolling_time', parseInt(String(values.rolling_time), 10)),
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
    setSubmitting(true);
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('feedAdd');
        const newEdge = payload?.setLinkedRecord(payload, 'node');
        if (newEdge) {
          const container = store.getRoot();
          const userId = container.getDataID();
          const userProxy = store.get(userId);
          if (userProxy) {
            const conn = ConnectionHandler.getConnection(
              userProxy,
              'Pagination_feeds',
              paginationOptions,
            );
            if (conn) {
              ConnectionHandler.insertEdgeBefore(conn, newEdge);
            }
          }
        }
        setSubmitting(false);
      },
      onCompleted: () => {
        resetForm();
      },
    });
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
    const allKeys = Object.keys(feedAttributes);
    const lastKey = R.last(allKeys);
    const newKey = lastKey
      ? lastKey + 1
      : 0;
    setFeedAttributes(R.assoc(newKey, {}, feedAttributes));
  };

  const handleRemoveAttribute = (i: string) => {
    setFeedAttributes(R.dissoc(i, feedAttributes));
  };

  const handleChangeField = (i: string, value: string) => {
    const newFeedAttribute = R.assoc('attribute', value, feedAttributes[i]);
    setFeedAttributes(R.assoc(i, newFeedAttribute, feedAttributes));
  };

  const handleChangeAttributeMapping = (i: string, type: string, value: string) => {
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
  const initialValues: FeedAddInput = isDuplicated && feed ? {
    name: `${feed.name} - copy `,
    description: feed.description,
    separator: feed.separator,
    filters: feed.filters,
    rolling_time: feed.rolling_time,
    include_header: feed.include_header,
    feed_types: feed.feed_types,
    authorized_members: feed.authorized_members,
    feed_attributes: feed.feed_attributes,
    feed_date_attribute: feed.feed_date_attribute,
    feed_public: feed.feed_public,
  } : {
    name: '',
    description: '',
    separator: ';',
    filters: '',
    rolling_time: 60,
    include_header: true,
    feed_types: [],
    authorized_members: [],
    feed_attributes: [],
    feed_date_attribute: 'created_at',
    feed_public: false,
  };
  return (
    <Drawer
      title={isDuplicated ? (t_i18n('Duplicate a feed')) : (t_i18n('Create a feed'))}
      variant={isFABReplaced || isDuplicated ? undefined : DrawerVariant.createWithPanel}
      controlledDial={isFABReplaced && !isDuplicated ? CreateFeedControlledDial : undefined }
      open={open}
      onClose={onHandleClose}
    >
      {({ onClose }) => (
        <QueryRenderer
          query={feedCreationAllTypesQuery}
          render={({ props: data }: { props: FeedCreationAllTypesQuery$data }) => {
            if (data && data.scoTypes && data.sdoTypes) {
              const resultSco = ((data as FeedCreationAllTypesQuery$data).scoTypes.edges ?? []).map((n) => ({
                label: t_i18n(`entity_${n.node.label}`),
                value: n.node.label,
                type: n.node.label,
              }));
              const resultSdo = ((data as FeedCreationAllTypesQuery$data).sdoTypes.edges ?? []).map((n) => ({
                label: t_i18n(`entity_${n.node.label}`),
                value: n.node.label,
                type: n.node.label,
              }));
              const result = [...resultSco, ...resultSdo];
              const entitiesTypes = R.sortWith(
                [R.ascend(R.prop('label'))],
                result,
              );

              return (
                <Formik<FeedAddInput>
                  initialValues={initialValues}
                  validationSchema={feedCreationValidation(t_i18n)}
                  onSubmit={onSubmit}
                  onReset={onClose}
                >
                  {({ values, submitForm, setFieldValue, handleReset, isSubmitting }) => (
                    <Form>
                      <Field
                        component={TextField}
                        variant="standard"
                        name="name"
                        label={t_i18n('Name')}
                        fullWidth={true}
                      />
                      <Field
                        component={TextField}
                        variant="standard"
                        name="description"
                        label={t_i18n('Description')}
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
                          {t_i18n('Make this feed public and available to anyone')}
                        </AlertTitle>
                        <FormControlLabel
                          control={<Switch />}
                          style={{ marginLeft: 1 }}
                          name="feed_public"
                          onChange={(_, checked) => setFieldValue('feed_public', checked)}
                          label={t_i18n('Public feed')}
                        />
                        {!values.feed_public && (
                          <ObjectMembersField
                            label={'Accessible for'}
                            style={fieldSpacingContainerStyle}
                            onChange={setFieldValue}
                            multiple={true}
                            helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
                            name="authorized_members"
                          />
                        )}
                      </Alert>
                      <Field
                        component={TextField}
                        variant="standard"
                        name="separator"
                        label={t_i18n('Separator')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <Field
                        component={TextField}
                        variant="standard"
                        type="number"
                        name="rolling_time"
                        label={t_i18n('Rolling time (in minutes)')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                        slotProps={{
                          input: {
                            endAdornment: (
                              <InputAdornment position="end">
                                <Tooltip
                                  title={t_i18n(
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
                        label={t_i18n('Base attribute')}
                        fullWidth={true}
                        multiple={false}
                        containerstyle={{ width: '100%', marginTop: 20 }}
                      >
                        <MenuItem key={'created_at'} value={'created_at'}>{t_i18n('Creation date')}</MenuItem>
                        <MenuItem key={'updated_at'} value={'updated_at'}>{t_i18n('Update date')}</MenuItem>
                      </Field>
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="feed_types"
                        onChange={(_: unknown, value: string[]) => handleSelectTypes(value)}
                        label={t_i18n('Entity types')}
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
                        label={t_i18n('Include headers in the feed')}
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
                                <Grid item xs="auto">
                                  <MuiTextField
                                    variant="standard"
                                    name="attribute"
                                    label={t_i18n('Column')}
                                    fullWidth={true}
                                    value={feedAttributes[i].attribute || ''}
                                    onChange={(event) => handleChangeField(i, event.target.value)}
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
                                        {t_i18n(`entity_${selectedType}`)}
                                      </InputLabel>
                                      <QueryRenderer
                                        query={
                                          stixCyberObservablesLinesAttributesQuery
                                        }
                                        variables={{
                                          elementType: [selectedType],
                                        }}
                                        render={({ props: resultProps }: { props: StixCyberObservablesLinesAttributesQuery$data }) => {
                                          if (
                                            resultProps
                                            && resultProps.schemaAttributeNames
                                          ) {
                                            const allAttributes = resultProps.schemaAttributeNames.edges.map((edge) => (edge.node));
                                            let attributes = allAttributes.filter((node) => (!ignoredAttributesInFeeds.includes(node.value) && !node.value.startsWith('i_')));

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
                                                value={feedAttributes[i]?.mappings
                                                    && feedAttributes[i]?.mappings?.[
                                                      selectedType
                                                    ]?.attribute}
                                                onChange={(event) => handleChangeAttributeMapping(
                                                  i,
                                                  selectedType,
                                                  event.target.value,
                                                )}
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
                          <div className={classes.buttonAdd}>
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
                          {t_i18n('Cancel')}
                        </Button>
                        <Button
                          variant="contained"
                          color="secondary"
                          onClick={submitForm}
                          disabled={isSubmitting || !areAttributesValid()}
                          classes={{ root: classes.button }}
                        >
                          {isDuplicated ? t_i18n('Duplicate') : t_i18n('Create')}
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
      )}
    </Drawer>
  );
};
const FeedCreationFragment = createFragmentContainer(FeedCreation, {
  feed: graphql`
    fragment FeedCreation on Feed {
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
    }`,
});
export default R.compose(inject18n)(FeedCreationFragment);
