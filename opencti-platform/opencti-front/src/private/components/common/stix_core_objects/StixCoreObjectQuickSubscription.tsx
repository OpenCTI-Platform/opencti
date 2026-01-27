import { ExpandLess, ExpandMore, KeyboardArrowRightOutlined, NotificationsOutlined } from '@mui/icons-material';

import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Drawer from '@components/common/drawer/Drawer';
import { stixCoreObjectTriggersUtils_triggers$key as FragmentKey } from '@components/common/stix_core_objects/__generated__/stixCoreObjectTriggersUtils_triggers.graphql';
import {
  stixCoreObjectTriggersUtilsPaginationQuery as TriggerQuery,
  stixCoreObjectTriggersUtilsPaginationQuery$data,
  stixCoreObjectTriggersUtilsPaginationQuery$variables,
} from '@components/common/stix_core_objects/__generated__/stixCoreObjectTriggersUtilsPaginationQuery.graphql';
import { stixCoreObjectTriggersFragment } from '@components/common/stix_core_objects/stixCoreObjectTriggersUtils';
import { Badge, ListItemButton, ListItemIcon, Stack, Typography } from '@mui/material';
import Alert from '@mui/material/Alert';
import Checkbox from '@mui/material/Checkbox';
import Collapse from '@mui/material/Collapse';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
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
import { Link } from 'react-router-dom';
import * as Yup from 'yup';
import AutocompleteField from '../../../../components/AutocompleteField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import Tag from '../../../../components/common/tag/Tag';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';
import { convertEventTypes, convertNotifiers, instanceEventTypesOptions } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { deserializeFilterGroupForFrontend, findFilterFromKey, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useComputeLink } from '../../../../utils/hooks/useAppData';
import useAuth from '../../../../utils/hooks/useAuth';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { deleteNode, insertNode } from '../../../../utils/store';
import { TriggerEventType, TriggerLiveAddInput, TriggerLiveCreationKnowledgeMutation } from '../../profile/triggers/__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { triggerMutationFieldPatch } from '../../profile/triggers/TriggerEditionOverview';
import { triggerLiveKnowledgeCreationMutation } from '../../profile/triggers/TriggerLiveCreation';
import { TriggerPopoverDeletionMutation } from '../../profile/triggers/TriggerPopover';
import NotifierField from '../form/NotifierField';

interface InstanceTriggerEditionFormValues {
  id: string;
  name: string;
  description: string | null;
  event_types: readonly FieldOption[];
  notifiers: readonly FieldOption[];
  filters: string | null;
}

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  nested: {
    margin: `0 ${theme.spacing(1)}`,
    width: 'auto',
    backgroundColor: theme.palette.background.nav,
  },
}));

interface StixCoreObjectQuickSubscriptionContentProps {
  triggerData: stixCoreObjectTriggersUtilsPaginationQuery$data;
  paginationOptions: stixCoreObjectTriggersUtilsPaginationQuery$variables;
  instanceId: string;
  instanceName: string;
  title?: string;
}

const EVENT_TYPES = {
  update: 'update' as TriggerEventType,
  delete: 'delete' as TriggerEventType,
};

const NOTIFIER_IDS = {
  userInterface: 'f4ee7b33-006a-4b0d-b57d-411ad288653d',
  defaultMailer: '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822',
};

const StixCoreObjectQuickSubscription: FunctionComponent<
  StixCoreObjectQuickSubscriptionContentProps
> = ({ triggerData, instanceId, paginationOptions, instanceName, title }) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const computeLink = useComputeLink();
  const draftContext = useDraftContext();
  const disabledInDraft = !!draftContext;

  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [expandedLines, setExpandedLines] = useState<boolean>(false);

  const [existingInstanceTriggersData, refetch] = useRefetchableFragment<TriggerQuery, FragmentKey>(stixCoreObjectTriggersFragment, triggerData);

  const existingInstanceTriggersEdges = existingInstanceTriggersData?.triggersKnowledge?.edges ?? [];
  const myInstanceTriggers = existingInstanceTriggersEdges.filter((e) => e.node.recipients?.some((r) => r.id === me.id)) ?? [];

  const [commitAddTrigger] = useApiMutation<TriggerLiveCreationKnowledgeMutation>(
    triggerLiveKnowledgeCreationMutation,
  );
  const [commitFieldPatch] = useApiMutation(triggerMutationFieldPatch);
  const [commitDeleteTrigger] = useApiMutation(TriggerPopoverDeletionMutation);

  const { triggersKnowledge, triggersKnowledgeCount } = existingInstanceTriggersData;

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
      event_types: [
        EVENT_TYPES.update,
        EVENT_TYPES.delete,
      ],
      notifiers: [
        NOTIFIER_IDS.userInterface,
        NOTIFIER_IDS.defaultMailer,
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
        handleClose();
        MESSAGING$.notifySuccess(
          'Instance trigger successfully created. You can click again on the bell to edit the options.',
        );
        refetch({ ...paginationOptions, after: null }, { fetchPolicy: 'network-only' });
      },
    });
  };

  const onSubmitUpdate: FormikConfig<InstanceTriggerEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    console.log('---- values', values);
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

  const renderForm = (
    instanceTrigger: InstanceTriggerEditionFormValues,
    firstTrigger: boolean,
    multipleInstanceTrigger: boolean,
  ) => {
    let instanceTriggerFilters: FilterGroup | null;
    if (instanceTrigger) {
      instanceTriggerFilters = deserializeFilterGroupForFrontend(
        instanceTrigger.filters,
      );
    }

    //
    const initValues = {
      name: title,
      event_types: [
        { value: EVENT_TYPES.update, label: t_i18n('Modification') },
        { value: EVENT_TYPES.delete, label: t_i18n('Deletion') },
      ],
      notifiers: [
        { value: NOTIFIER_IDS.userInterface, label: t_i18n('User interface') },
        { value: NOTIFIER_IDS.defaultMailer, label: t_i18n('Default mailer') },
      ],
    };

    return (
      <Stack
        key={instanceTrigger?.id}
        gap={3}
      >
        <Stack gap={1}>
          <Stack
            direction="row"
            alignItems="center"
            gap={1}
          >
            <Typography variant="h6">{t_i18n('Subscribe')}</Typography>
            <Tag
              label={instanceTrigger ? t_i18n('Subscribed') : t_i18n('Not subscribed')}
              color={instanceTrigger ? theme.palette.designSystem.tertiary.green[600] : undefined}
            />
          </Stack>

          <Formik
            initialValues={instanceTrigger ?? initValues}
            validationSchema={liveTriggerValidation}
            onSubmit={onSubmitUpdate}
          >
            {({ submitForm, isSubmitting, values, setFieldValue }) => (
              <Form
                style={{
                  border: `1px solid ${theme.palette.designSystem.border.main}`,
                  borderRadius: '4px',
                  padding: '16px',
                }}
              >
                <Stack gap={3}>
                  <div>
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
                  </div>
                </Stack>

                <FormButtonContainer>
                  {
                    instanceTrigger ? (
                      <>
                        <Button
                          variant="secondary"
                          intent="destructive"
                          onClick={
                            multipleInstanceTrigger
                              ? () => submitRemove(values.id, values.filters)
                              : () => submitDelete(values.id)
                          }
                          disabled={deleting}
                        >
                          {multipleInstanceTrigger ? t_i18n('Remove') : t_i18n('Unsubscribe')}
                        </Button>
                        <Button
                          onClick={submitForm}
                          disabled={isSubmitting}
                        >
                          {t_i18n('Update')}
                        </Button>
                      </>
                    ) : (
                      <Button
                        onClick={createInstanceTrigger}
                        disabled={isSubmitting}
                      >
                        {t_i18n('Subscribe')}
                      </Button>
                    )
                  }
                </FormButtonContainer>
              </Form>
            )}
          </Formik>
        </Stack>

        <Stack>
          <Typography variant="h6">{t_i18n('Subscribers list')} ({triggersKnowledge?.edges?.length})</Typography>
          <List>
            {triggersKnowledge?.edges.map((triggerEdge) => (
              <React.Fragment key={triggerEdge.node.id}>
                {triggerEdge.node.recipients?.map((recipient) => (
                  <ListItemButton
                    key={recipient.id}
                    divider={true}
                    component={Link}
                    to={`${computeLink(recipient)}`}
                  >
                    <ListItemIcon>
                      <ItemIcon type={recipient.entity_type} />
                    </ListItemIcon>
                    <ListItemText primary={recipient.name} />
                    <ListItemIcon sx={{ justifyContent: 'flex-end' }}>
                      <KeyboardArrowRightOutlined />
                    </ListItemIcon>
                  </ListItemButton>
                ))}
              </React.Fragment>
            ))}
          </List>
        </Stack>
      </Stack>
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

  const renderContent = () => {
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
        title={t_i18n('Manage subscription')}
        open={open}
        onClose={handleClose}
      >
        <Stack gap={3}>
          <Alert severity="info" variant="outlined">
            {t_i18n('When subscribing to an object, it notifies you about modifications of this object, containers (reports, groupings, etc.) about this object as well as creation and deletion of relationships related to this object.')}
          </Alert>

          {
            renderForm(
              firstInstanceTriggerToDisplay?.values ?? null,
              true,
              firstInstanceTriggerToDisplay?.multiple ?? null,
            )
          }

          {otherInstanceTriggersToDisplay.length > 0 && (
            <List>
              <ListItem
                divider={true}
                disablePadding
                secondaryAction={(
                  <IconButton
                    onClick={handleToggleLine}
                    aria-haspopup="true"
                  >
                    {expandedLines ? <ExpandLess /> : <ExpandMore />}
                  </IconButton>
                )}
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
                {otherInstanceTriggersToDisplay.map((instanceTrigger) => renderForm(
                  instanceTrigger.values,
                  false,
                  instanceTrigger.multiple,
                ))}
              </Collapse>
            </List>
          )}
        </Stack>
      </Drawer>
    );
  };

  const tooltip = disabledInDraft
    ? t_i18n('Not available in draft')
    : t_i18n('Subscribe to updates (modifications and new relations)');

  return (
    <>
      <Tooltip
        title={tooltip}
        placement="bottom-start"
      >
        <Badge badgeContent={triggersKnowledgeCount} color="primary">
          <ToggleButton
            onClick={() => !disabledInDraft && handleOpen()}
            value="quick-subscription"
            size="small"
          >
            <NotificationsOutlined
              fontSize="small"
              color={disabledInDraft ? 'disabled' : 'primary'}
            />
          </ToggleButton>
        </Badge>
      </Tooltip>
      {renderContent()}
    </>
  );
};

export default StixCoreObjectQuickSubscription;
