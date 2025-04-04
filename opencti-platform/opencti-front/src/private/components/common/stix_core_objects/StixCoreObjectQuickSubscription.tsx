import { ExpandLess, ExpandMore, NotificationsOutlined } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import { OverridableStringUnion } from '@mui/types';
import Checkbox from '@mui/material/Checkbox';
import Collapse from '@mui/material/Collapse';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { makeStyles, useTheme } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { pick, uniq } from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { useRefetchableFragment } from 'react-relay';
import * as Yup from 'yup';
import Drawer from '@components/common/drawer/Drawer';
import { stixCoreObjectTriggersFragment } from '@components/common/stix_core_objects/stixCoreObjectTriggersUtils';
import {
  stixCoreObjectTriggersUtilsPaginationQuery as TriggerQuery,
  stixCoreObjectTriggersUtilsPaginationQuery$data,
  stixCoreObjectTriggersUtilsPaginationQuery$variables,
} from '@components/common/stix_core_objects/__generated__/stixCoreObjectTriggersUtilsPaginationQuery.graphql';
import { stixCoreObjectTriggersUtils_triggers$key as FragmentKey } from '@components/common/stix_core_objects/__generated__/stixCoreObjectTriggersUtils_triggers.graphql';
import { ListItemButton, SvgIconPropsColorOverrides } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import AutocompleteField from '../../../../components/AutocompleteField';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';
import { convertEventTypes, convertNotifiers, instanceEventTypesOptions } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { deleteNode, insertNode } from '../../../../utils/store';
import useAuth from '../../../../utils/hooks/useAuth';
import { TriggerLiveAddInput, TriggerLiveCreationKnowledgeMutation } from '../../profile/triggers/__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { triggerMutationFieldPatch } from '../../profile/triggers/TriggerEditionOverview';
import { instanceTriggerDescription, triggerLiveKnowledgeCreationMutation } from '../../profile/triggers/TriggerLiveCreation';
import { TriggerPopoverDeletionMutation } from '../../profile/triggers/TriggerPopover';
import NotifierField from '../form/NotifierField';
import { Option } from '../form/ReferenceField';
import { deserializeFilterGroupForFrontend, findFilterFromKey, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

interface InstanceTriggerEditionFormValues {
  id: string;
  name: string;
  description: string | null;
  event_types: readonly Option[];
  notifiers: readonly Option[];
  filters: string | null;
}

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    textAlign: 'right',
  },
  updateButton: {
    marginLeft: theme.spacing(2),
  },
  deleteButton: {
    marginLeft: theme.spacing(2),
    backgroundColor: '#f44336',
    borderColor: '#f44336',
    color: '#ffffff',
    '&:hover': {
      backgroundColor: '#c62828',
      borderColor: '#c62828',
    },
  },
  container: {
    padding: theme.spacing(1),
  },
  subcontainer: {
    padding: `${theme.spacing(1)} ${theme.spacing(3)}`,
  },
  nested: {
    margin: `0 ${theme.spacing(1)}`,
    width: 'auto',
    backgroundColor: theme.palette.background.nav,
  },
}));

interface StixCoreObjectQuickSubscriptionContentProps {
  triggerData: stixCoreObjectTriggersUtilsPaginationQuery$data
  paginationOptions: stixCoreObjectTriggersUtilsPaginationQuery$variables;
  instanceId: string;
  instanceName: string;
}

const StixCoreObjectQuickSubscription: FunctionComponent<
StixCoreObjectQuickSubscriptionContentProps
> = ({ triggerData, instanceId, paginationOptions, instanceName }) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const draftContext = useDraftContext();
  const disabledInDraft = !!draftContext;

  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [expandedLines, setExpandedLines] = useState<boolean>(false);

  const [existingInstanceTriggersData, refetch] = useRefetchableFragment<TriggerQuery, FragmentKey>(stixCoreObjectTriggersFragment, triggerData);

  const existingInstanceTriggersEdges = existingInstanceTriggersData?.triggersKnowledge?.edges ?? [];
  const myInstanceTriggers = existingInstanceTriggersEdges.filter((e) => e.node.recipients?.some((r) => r.id === me.id)) ?? [];
  const triggerUpdate = myInstanceTriggers.length > 0;

  const [commitAddTrigger] = useApiMutation<TriggerLiveCreationKnowledgeMutation>(
    triggerLiveKnowledgeCreationMutation,
  );
  const [commitFieldPatch] = useApiMutation(triggerMutationFieldPatch);
  const [commitDeleteTrigger] = useApiMutation(TriggerPopoverDeletionMutation);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleToggleLine = () => {
    setExpandedLines(!expandedLines);
  };

  const liveTriggerValidation = () => Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    event_types: Yup.array()
      .min(1, t_i18n('Minimum one event type'))
      .required(t_i18n('This field is required')),
    notifiers: Yup.array().required(t_i18n('This field is required')),
  });

  const createInstanceTrigger = () => {
    const finalValues: TriggerLiveAddInput = {
      name: instanceName,
      description: '',
      event_types: ['update', 'delete'],
      notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822',
      ],
      instance_trigger: true,
      filters: serializeFilterGroupForBackend({
        mode: 'and',
        filters: [
          {
            key: 'connectedToId',
            values: [instanceId],
            operator: 'eq',
            mode: 'or',
          },
        ],
        filterGroups: [],
      }),
    };
    commitAddTrigger({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_quickSubscription__triggersKnowledge',
          paginationOptions,
          'triggerKnowledgeLiveAdd',
        );
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(
          'Instance trigger successfully created. You can click again on the bell to edit the options.',
        );
        refetch({ ...paginationOptions, after: null }, { fetchPolicy: 'network-only' });
      },
    });
  };

  const onSubmitUpdate: FormikConfig<InstanceTriggerEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const finalValues = [
      {
        key: 'name',
        value: [values.name],
      },
      {
        key: 'event_types',
        value: uniq(values.event_types.map((n) => n.value)),
      },
      {
        key: 'notifiers',
        value: uniq(values.notifiers.map((n) => n.value)),
      },
    ];
    commitFieldPatch({
      variables: {
        id: values.id,
        input: finalValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const submitDelete = (triggerIdToDelete: string) => {
    setDeleting(true);
    commitDeleteTrigger({
      variables: {
        id: triggerIdToDelete,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_quickSubscription__triggersKnowledge',
          paginationOptions,
          triggerIdToDelete,
        );
      },
      onCompleted: () => {
        refetch({ ...paginationOptions, after: null }, { fetchPolicy: 'network-only' });
        setDeleting(false);
        handleClose();
      },
    });
  };

  const submitRemove = (triggerIdToUpdate: string, filters: string | null) => {
    setDeleting(true);
    const filterGroup = deserializeFilterGroupForFrontend(filters);
    const newInstanceValues = findFilterFromKey(
      filterGroup?.filters ?? [],
      'connectedToId',
    )?.values?.filter((id) => id !== instanceId) ?? [];
    const newInstanceFilters = filterGroup && newInstanceValues.length > 0
      ? {
        ...filterGroup,
        filters: [
          ...filterGroup.filters.filter(
            (f) => f.key !== 'connectedToId' || f.operator !== 'eq',
          ),
          {
            key: 'connectedToId',
            values: newInstanceValues,
            operator: 'eq',
            mode: 'or',
          },
        ],
      }
      : {
        mode: filterGroup?.mode ?? 'and',
        filters:
              filterGroup?.filters.filter(
                (f) => f.key !== 'connectedToId' || f.operator !== 'eq',
              ) ?? [],
        filterGroups: filterGroup?.filterGroups ?? [],
      };
    commitFieldPatch({
      variables: {
        id: triggerIdToUpdate,
        input: [
          {
            key: 'filters',
            value: serializeFilterGroupForBackend(newInstanceFilters),
          },
        ],
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_quickSubscription__triggersKnowledge',
          paginationOptions,
          triggerIdToUpdate,
        );
      },
      onCompleted: () => {
        refetch({ ...paginationOptions, after: null }, { fetchPolicy: 'network-only' });
        setDeleting(false);
      },
    });
  };

  const updateInstanceTriggerContent = (
    instanceTrigger: InstanceTriggerEditionFormValues,
    firstTrigger: boolean,
    multipleInstanceTrigger: boolean,
  ) => {
    const instanceTriggerFilters = deserializeFilterGroupForFrontend(
      instanceTrigger.filters,
    );
    return (
      <div
        key={instanceTrigger.id}
        className={firstTrigger ? classes.container : classes.subcontainer}
      >
        <Formik
          initialValues={instanceTrigger}
          validationSchema={liveTriggerValidation}
          onSubmit={onSubmitUpdate}
        >
          {({ submitForm, isSubmitting, values, setFieldValue }) => (
            <Form style={{ margin: `${theme.spacing(1)} 0` }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <NotifierField name="notifiers" onChange={setFieldValue} />
              <Field
                component={AutocompleteField}
                name="event_types"
                style={fieldSpacingContainerStyle}
                multiple={true}
                textfieldprops={{
                  variant: 'standard',
                  label: t_i18n('Triggering on'),
                }}
                options={instanceEventTypesOptions}
                onChange={setFieldValue}
                renderOption={(
                  props: React.HTMLAttributes<HTMLLIElement>,
                  option: { value: string; label: string },
                ) => (
                  <MenuItem value={option.value} {...props}>
                    <Checkbox
                      checked={values.event_types
                        .map((n) => n.value)
                        .includes(option.value)}
                    />
                    <ListItemText primary={option.label} />
                  </MenuItem>
                )}
              />
              {multipleInstanceTrigger && instanceTriggerFilters && (
                <div style={{ ...fieldSpacingContainerStyle }}>
                  <FilterIconButton
                    filters={instanceTriggerFilters}
                    styleNumber={3}
                    redirection
                    entityTypes={['Instance']}
                  />
                </div>
              )}
              <div
                className={classes.buttons}
                style={{ marginTop: firstTrigger ? 20 : 40 }}
              >
                <Button
                  variant="contained"
                  onClick={
                    multipleInstanceTrigger
                      ? () => submitRemove(values.id, values.filters)
                      : () => submitDelete(values.id)
                  }
                  disabled={deleting}
                  classes={{ root: classes.deleteButton }}
                >
                  {multipleInstanceTrigger ? t_i18n('Remove') : t_i18n('Delete')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.updateButton }}
                >
                  {t_i18n('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    );
  };

  const isInstanceTriggerOnMultipleInstances = (
    triggerValue: InstanceTriggerEditionFormValues,
  ) => {
    const filters = deserializeFilterGroupForFrontend(triggerValue.filters);
    if (filters) {
      const connectedToIdFilter = findFilterFromKey(
        filters.filters,
        'connectedToId',
      );
      return (
        connectedToIdFilter?.values && connectedToIdFilter.values.length > 1
      );
    }
    return false;
  };

  const updateInstanceTrigger = () => {
    const triggerValues = myInstanceTriggers
      .filter((l) => l)
      .map((n) => ({
        ...pick(['id', 'name', 'description', 'filters'], n?.node),
        notifiers: convertNotifiers(n?.node),
        event_types: convertEventTypes(n?.node),
      })) as InstanceTriggerEditionFormValues[];
    const uniqInstanceTriggers = triggerValues
      .filter((n) => !isInstanceTriggerOnMultipleInstances(n))
      .map((n) => ({ values: n, multiple: false }));
    const multipleInstanceTriggers = triggerValues
      .filter((n) => isInstanceTriggerOnMultipleInstances(n))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((n) => ({ values: n, multiple: true }));
    const sortedTriggersToDisplay = uniqInstanceTriggers.concat(
      multipleInstanceTriggers,
    );
    const firstInstanceTriggerToDisplay = sortedTriggersToDisplay[0];
    const otherInstanceTriggersToDisplay = sortedTriggersToDisplay.slice(1); // the other instance triggers
    return (
      <Drawer
        title={t_i18n('Update subscription')}
        open={open}
        onClose={handleClose}
      >
        <>
          <Alert severity="info">
            {t_i18n(instanceTriggerDescription)}
          </Alert>
          <div>
            {updateInstanceTriggerContent(
              firstInstanceTriggerToDisplay.values,
              true,
              firstInstanceTriggerToDisplay.multiple,
            )}
          </div>
          {otherInstanceTriggersToDisplay.length > 0 && (
            <List>
              <ListItem
                divider={true}
                disablePadding
                secondaryAction={
                  <IconButton
                    onClick={handleToggleLine}
                    aria-haspopup="true"
                    size="large"
                  >
                    {expandedLines ? <ExpandLess /> : <ExpandMore />}
                  </IconButton>
              }
              >
                <ListItemButton
                  classes={{ root: classes.nested }}
                  onClick={handleToggleLine}
                >
                  <ListItemText
                    primary={`${otherInstanceTriggersToDisplay.length} ${t_i18n(
                      'other trigger(s) related to this entity',
                    )}`}
                  />
                </ListItemButton>
              </ListItem>
              <Collapse in={expandedLines}>
                {otherInstanceTriggersToDisplay.map((instanceTrigger) => updateInstanceTriggerContent(
                  instanceTrigger.values,
                  false,
                  instanceTrigger.multiple,
                ))}
              </Collapse>
            </List>
          )}
        </>
      </Drawer>
    );
  };

  const title = disabledInDraft ? t_i18n('Not available in draft') : t_i18n('Subscribe to updates (modifications and new relations)');
  let color: OverridableStringUnion<'inherit' | 'disabled' | 'secondary' | 'primary' | 'action' | 'info' | 'success' | 'warning' | 'error', SvgIconPropsColorOverrides> | undefined;
  if (disabledInDraft) {
    color = 'disabled';
  } else {
    color = triggerUpdate ? 'secondary' : 'primary';
  }
  return (
    <>
      <Tooltip
        title={title}
        placement={'bottom-start'}
      >
        <ToggleButton
          onClick={() => !disabledInDraft && (triggerUpdate ? handleOpen() : createInstanceTrigger())}
          value="quick-subscription"
          size="small"
          style={{ marginRight: 3 }}
        >
          <NotificationsOutlined
            fontSize="small"
            color={color}
          />
        </ToggleButton>
      </Tooltip>
      {triggerUpdate && updateInstanceTrigger()}
    </>
  );
};

export default StixCoreObjectQuickSubscription;
