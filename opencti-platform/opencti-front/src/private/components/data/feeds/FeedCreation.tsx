import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
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
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Divider from '@mui/material/Divider';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { FeedCreationAllTypesQuery$data } from '@components/data/feeds/__generated__/FeedCreationAllTypesQuery.graphql';
import { FeedAttributeMappingInput } from '@components/data/feeds/__generated__/FeedEditionMutation.graphql';
import { StixCyberObservablesLinesAttributesQuery$data } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservablesLinesAttributesQuery.graphql';
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
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { PaginationOptions } from '../../../../components/list_lines';
import useAuth, { FilterDefinition } from '../../../../utils/hooks/useAuth';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useTheme } from '@mui/material/styles';

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
  authorized_members: FieldOption[];
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
    entityType="Feed"
    {...props}
  />
);

const FeedCreation: FunctionComponent<FeedCreationFormProps> = (props) => {
  const { onDrawerClose, open, paginationOptions, isDuplicated, feed } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { schema } = useAuth();

  const getRelationshipTypesForEntity = (entityType: string) => {
    const relTypes = new Set<string>();
    schema.schemaRelationsTypesMapping.forEach((values, key) => {
      if (key.startsWith(`${entityType}_`) || key.endsWith(`_${entityType}`)) {
        values.forEach((v: string) => relTypes.add(v));
      }
    });
    relTypes.add('related-to');
    return Array.from(relTypes).sort();
  };

  const getTargetTypesForRelationship = (entityType: string, relType: string) => {
    const targets = new Set<string>();
    schema.schemaRelationsTypesMapping.forEach((values, key) => {
      if (values.includes(relType) || relType === 'related-to') {
        const [from, to] = key.split('_');
        if (from === entityType) targets.add(to);
        if (to === entityType) targets.add(from);
      }
    });
    return Array.from(targets).sort();
  };

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
      multi_match_strategy: n.multi_match_strategy ?? undefined,
      multi_match_separator: n.multi_match_separator ?? undefined,
      mappings: R.values(n.mappings).map((m) => ({
        type: m.type,
        attribute: m.attribute,
        relationship_type: m.relationship_type ?? undefined,
        target_entity_type: m.target_entity_type ?? undefined,
      })),
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
      ) {
        return false;
      }
      const invalidMappings = R.values(feedAttribute.mappings).filter((m) => {
        if (!m.type || m.type.length === 0 || !m.attribute || m.attribute.length === 0) return true;
        if (m.relationship_type && !m.target_entity_type) return true;
        if (!m.relationship_type && m.target_entity_type) return true;
        return false;
      });
      if (invalidMappings.length > 0) return false;
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
    const existingMapping = feedAttributes[i]?.mappings?.[type] || {};
    const mapping = { ...existingMapping, type, attribute: value };
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

  const handleToggleNeighborMode = (i: string, type: string) => {
    const existingMapping = feedAttributes[i]?.mappings?.[type] || {};
    const isNeighbor = 'relationship_type' in existingMapping;
    let mapping;
    if (isNeighbor) {
      mapping = { type, attribute: '' };
    } else {
      mapping = { type, attribute: '', relationship_type: '', target_entity_type: '' };
    }
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

  const handleChangeNeighborMapping = (i: string, type: string, field: string, value: string) => {
    const existingMapping = feedAttributes[i]?.mappings?.[type] || { type };
    const mapping = { ...existingMapping, [field]: value };
    if (field === 'relationship_type') {
      mapping.target_entity_type = '';
      mapping.attribute = '';
    }
    if (field === 'target_entity_type') {
      mapping.attribute = '';
    }
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

  const handleChangeMultiMatchStrategy = (i: string, value: string) => {
    const newFeedAttribute = R.assoc('multi_match_strategy', value, feedAttributes[i]);
    setFeedAttributes(R.assoc(i, newFeedAttribute, feedAttributes));
  };

  const handleChangeMultiMatchSeparator = (i: string, value: string) => {
    const newFeedAttribute = R.assoc('multi_match_separator', value, feedAttributes[i]);
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
      controlledDial={!isDuplicated ? CreateFeedControlledDial : undefined}
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
                            label="Accessible for"
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
                        <MenuItem key="created_at" value="created_at">{t_i18n('Creation date')}</MenuItem>
                        <MenuItem key="updated_at" value="updated_at">{t_i18n('Update date')}</MenuItem>
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
                      <Box sx={{
                        paddingTop: 4,
                        display: 'flex',
                        alignItems: 'center',
                        gap: theme.spacing(1),
                        marginBottom: theme.spacing(1),
                      }}
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
                        redirection
                        searchContext={{ entityTypes: selectedTypes }}
                      />
                      {selectedTypes.length > 0 && (
                        <div
                          className={classes.container}
                          style={{ marginTop: 20 }}
                        >
                          {Object.keys(feedAttributes).map((i) => {
                            const hasNeighborMapping = R.values(feedAttributes[i]?.mappings || {}).some(
                              (m) => !!m?.relationship_type,
                            );
                            return (
                              <div key={i} className={classes.step}>
                                <IconButton
                                  disabled={feedAttributes.length === 1}
                                  aria-label="Delete"
                                  className={classes.stepCloseButton}
                                  onClick={() => handleRemoveAttribute(i)}
                                >
                                  <CancelOutlined fontSize="small" />
                                </IconButton>
                                <Box sx={{ width: '100%' }}>
                                  <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-end', mb: 2 }}>
                                    <MuiTextField
                                      variant="standard"
                                      name="attribute"
                                      label={t_i18n('Column name')}
                                      fullWidth={true}
                                      value={feedAttributes[i].attribute || ''}
                                      onChange={(event) => handleChangeField(i, event.target.value)}
                                      sx={{ flex: 1 }}
                                    />
                                    {hasNeighborMapping && (
                                      <>
                                        <FormControl variant="standard" sx={{ minWidth: 140 }}>
                                          <InputLabel>{t_i18n('Multi-match')}</InputLabel>
                                          <Select
                                            value={feedAttributes[i]?.multi_match_strategy || 'list'}
                                            onChange={(event) => handleChangeMultiMatchStrategy(i, event.target.value)}
                                          >
                                            <MenuItem value="list">{t_i18n('All (list)')}</MenuItem>
                                            <MenuItem value="first">{t_i18n('First match')}</MenuItem>
                                          </Select>
                                        </FormControl>
                                        {(feedAttributes[i]?.multi_match_strategy || 'list') === 'list' && (
                                          <MuiTextField
                                            variant="standard"
                                            label={t_i18n('List separator')}
                                            value={feedAttributes[i]?.multi_match_separator ?? ','}
                                            onChange={(event) => handleChangeMultiMatchSeparator(i, event.target.value)}
                                            sx={{ width: 100 }}
                                            slotProps={{ htmlInput: { maxLength: 3 } }}
                                          />
                                        )}
                                      </>
                                    )}
                                  </Box>
                                  {selectedTypes.map((selectedType, typeIndex) => {
                                    const currentMapping = feedAttributes[i]?.mappings?.[selectedType];
                                    const isNeighborMode = !!currentMapping?.relationship_type || currentMapping?.relationship_type === '';
                                    return (
                                      <Box key={selectedType}>
                                        {typeIndex > 0 && <Divider sx={{ my: 1.5 }} />}
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                                          <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                            {t_i18n(`entity_${selectedType}`)}
                                          </Typography>
                                          <Chip
                                            label={isNeighborMode ? t_i18n('Relationship') : t_i18n('Direct')}
                                            size="small"
                                            color={isNeighborMode ? 'secondary' : 'default'}
                                            variant="outlined"
                                            onClick={() => handleToggleNeighborMode(i, selectedType)}
                                            sx={{ cursor: 'pointer', fontSize: '0.75rem', height: 22 }}
                                          />
                                        </Box>
                                        {isNeighborMode ? (
                                          <Grid container spacing={2}>
                                            <Grid item xs={4}>
                                              <FormControl variant="standard" fullWidth>
                                                <InputLabel>{t_i18n('Relationship type')}</InputLabel>
                                                <Select
                                                  value={currentMapping?.relationship_type || ''}
                                                  onChange={(event) => handleChangeNeighborMapping(i, selectedType, 'relationship_type', event.target.value)}
                                                >
                                                  {getRelationshipTypesForEntity(selectedType).map((rt) => (
                                                    <MenuItem key={rt} value={rt}>
                                                      {t_i18n(`relationship_${rt}`)}
                                                    </MenuItem>
                                                  ))}
                                                </Select>
                                              </FormControl>
                                            </Grid>
                                            <Grid item xs={4}>
                                              <FormControl variant="standard" fullWidth disabled={!currentMapping?.relationship_type}>
                                                <InputLabel>{t_i18n('Target type')}</InputLabel>
                                                <Select
                                                  value={currentMapping?.target_entity_type || ''}
                                                  onChange={(event) => handleChangeNeighborMapping(i, selectedType, 'target_entity_type', event.target.value)}
                                                >
                                                  {currentMapping?.relationship_type
                                                    && getTargetTypesForRelationship(selectedType, currentMapping.relationship_type).map((tt) => (
                                                      <MenuItem key={tt} value={tt}>
                                                        {t_i18n(`entity_${tt}`)}
                                                      </MenuItem>
                                                    ))}
                                                </Select>
                                              </FormControl>
                                            </Grid>
                                            <Grid item xs={4}>
                                              <FormControl variant="standard" fullWidth disabled={!currentMapping?.target_entity_type}>
                                                <InputLabel>{t_i18n('Attribute')}</InputLabel>
                                                {currentMapping?.target_entity_type ? (
                                                  <QueryRenderer
                                                    query={stixCyberObservablesLinesAttributesQuery}
                                                    variables={{ elementType: [currentMapping.target_entity_type] }}
                                                    render={({ props: resultProps }: { props: StixCyberObservablesLinesAttributesQuery$data }) => {
                                                      if (resultProps?.schemaAttributeNames) {
                                                        let attributes = resultProps.schemaAttributeNames.edges
                                                          .map((edge) => edge.node)
                                                          .filter((node) => !ignoredAttributesInFeeds.includes(node.value) && !node.value.startsWith('i_'));
                                                        if (attributes.some((n) => n.value === 'hashes')) {
                                                          attributes = R.sortBy(R.prop('value'), [
                                                            ...attributes,
                                                            { value: 'hashes.MD5' },
                                                            { value: 'hashes.SHA-1' },
                                                            { value: 'hashes.SHA-256' },
                                                            { value: 'hashes.SHA-512' },
                                                          ].filter((n) => n.value !== 'hashes'));
                                                        }
                                                        return (
                                                          <Select
                                                            value={currentMapping?.attribute || ''}
                                                            onChange={(event) => handleChangeAttributeMapping(i, selectedType, event.target.value)}
                                                          >
                                                            {attributes.map((attr) => (
                                                              <MenuItem key={attr.value} value={attr.value}>{attr.value}</MenuItem>
                                                            ))}
                                                          </Select>
                                                        );
                                                      }
                                                      return <Select disabled value="" />;
                                                    }}
                                                  />
                                                ) : <Select disabled value="" />}
                                              </FormControl>
                                            </Grid>
                                          </Grid>
                                        ) : (
                                          <FormControl variant="standard" fullWidth>
                                            <InputLabel>{t_i18n('Attribute')}</InputLabel>
                                            <QueryRenderer
                                              query={stixCyberObservablesLinesAttributesQuery}
                                              variables={{ elementType: [selectedType] }}
                                              render={({ props: resultProps }: { props: StixCyberObservablesLinesAttributesQuery$data }) => {
                                                if (resultProps?.schemaAttributeNames) {
                                                  let attributes = resultProps.schemaAttributeNames.edges
                                                    .map((edge) => edge.node)
                                                    .filter((node) => !ignoredAttributesInFeeds.includes(node.value) && !node.value.startsWith('i_'));
                                                  if (attributes.some((n) => n.value === 'hashes')) {
                                                    attributes = R.sortBy(R.prop('value'), [
                                                      ...attributes,
                                                      { value: 'hashes.MD5' },
                                                      { value: 'hashes.SHA-1' },
                                                      { value: 'hashes.SHA-256' },
                                                      { value: 'hashes.SHA-512' },
                                                    ].filter((n) => n.value !== 'hashes'));
                                                  }
                                                  return (
                                                    <Select
                                                      value={currentMapping?.attribute || ''}
                                                      onChange={(event) => handleChangeAttributeMapping(i, selectedType, event.target.value)}
                                                    >
                                                      {attributes.map((attr) => (
                                                        <MenuItem key={attr.value} value={attr.value}>{attr.value}</MenuItem>
                                                      ))}
                                                    </Select>
                                                  );
                                                }
                                                return <Select disabled value="" />;
                                              }}
                                            />
                                          </FormControl>
                                        )}
                                      </Box>
                                    );
                                  })}
                                </Box>
                              </div>
                            );
                          })}
                          <div className={classes.buttonAdd}>
                            <IconButton
                              disabled={selectedTypes.length === 0}
                              size="small"
                              onClick={() => handleAddAttribute()}
                              classes={{ root: classes.buttonAdd }}
                            >
                              <AddOutlined fontSize="small" />
                            </IconButton>
                          </div>
                        </div>
                      )}
                      <div className="clearfix" />
                      <FormButtonContainer>
                        <Button
                          variant="secondary"
                          onClick={handleReset}
                          disabled={isSubmitting}
                        >
                          {t_i18n('Cancel')}
                        </Button>
                        <Button
                          onClick={submitForm}
                          disabled={isSubmitting || !areAttributesValid()}
                        >
                          {isDuplicated ? t_i18n('Duplicate') : t_i18n('Create')}
                        </Button>
                      </FormButtonContainer>
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
        multi_match_strategy
        multi_match_separator
        mappings {
          type
          attribute
          relationship_type
          target_entity_type
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
