import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { Close, ExpandLess, ExpandMore, NotificationsOutlined } from '@mui/icons-material';
import React, { FunctionComponent, useState } from 'react';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import Button from '@mui/material/Button';
import { pick, uniq } from 'ramda';
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery } from 'react-relay';
import { makeStyles } from '@mui/styles';
import Collapse from '@mui/material/Collapse';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../../components/i18n';
import { triggerMutationFieldPatch } from '../../profile/triggers/TriggerEditionOverview';
import { TriggerPopoverDeletionMutation } from '../../profile/triggers/TriggerPopover';
import TextField from '../../../../components/TextField';
import { deleteNode, insertNode } from '../../../../utils/store';
import { Theme } from '../../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import {
  StixCoreObjectQuickSubscriptionContentPaginationQuery,
  StixCoreObjectQuickSubscriptionContentPaginationQuery$data,
  StixCoreObjectQuickSubscriptionContentPaginationQuery$variables,
} from './__generated__/StixCoreObjectQuickSubscriptionContentPaginationQuery.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';
import { convertEventTypes, convertOutcomes } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import FilterIconButton from '../../../../components/FilterIconButton';
import { TriggerLine_node$data } from '../../profile/triggers/__generated__/TriggerLine_node.graphql';
import { instanceTriggerDescription, triggerLiveKnowledgeCreationMutation } from '../../profile/triggers/TriggerLiveCreation';
import {
  TriggerLiveAddInput,
  TriggerLiveCreationKnowledgeMutation,
} from '../../profile/triggers/__generated__/TriggerLiveCreationKnowledgeMutation.graphql';

export const stixCoreObjectQuickSubscriptionContentQuery = graphql`
    query StixCoreObjectQuickSubscriptionContentPaginationQuery(
        $filters: [TriggersFiltering!]
        $first: Int
    ) {
        triggersKnowledge(
            filters: $filters
            first: $first
        ) @connection(key: "Pagination_triggersKnowledge") {
            edges {
                node {
                    id
                    name
                    trigger_type
                    event_types
                    description
                    filters
                    created
                    modified
                    outcomes
                    resolved_instance_filters {
                        id
                        valid
                        value
                    }
                }
            }
        }
    }
`;

interface InstanceTriggerEditionFormValues {
  id: string;
  name: string;
  description: string | null;
  event_types: readonly {
    label: string,
    value: string
  }[];
  outcomes: readonly {
    label: string,
    value: string
  }[];
  filters: string | null,
  resolved_instance_filters?: TriggerLine_node$data['resolved_instance_filters'],
}

const useStyles = makeStyles<Theme>((theme) => ({
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
  title: {
    float: 'left',
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
    padding: '10px 20px 20px 20px',
  },
  subcontainer: {
    padding: '10px 20px 20px 40px',
  },
  nested: {
    marginLeft: '20px',
    marginRight: '20px',
    width: 'auto',
    backgroundColor: theme.palette.background.nav,
  },
}));

interface StixCoreObjectQuickSubscriptionContentProps {
  queryRef: PreloadedQuery<StixCoreObjectQuickSubscriptionContentPaginationQuery>,
  paginationOptions: StixCoreObjectQuickSubscriptionContentPaginationQuery$variables,
  instanceId: string,
  instanceName: string,
}

const StixCoreObjectQuickSubscriptionContent: FunctionComponent<StixCoreObjectQuickSubscriptionContentProps> = ({
  queryRef,
  paginationOptions,
  instanceId,
  instanceName,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [expandedLines, setExpandedLines] = useState<boolean>(false);

  const outcomesOptions = [
    {
      value: 'f4ee7b33-006a-4b0d-b57d-411ad288653d',
      label: t('User interface'),
    },
    {
      value: '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822',
      label: t('Email'),
    },
  ];
  const outcomesOptionsMap: Record<string, string> = {
    'f4ee7b33-006a-4b0d-b57d-411ad288653d': t('User interface'),
    '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822': t('Email'),
  };

  const instanceEventTypesOptions = [
    { value: 'update', label: t('Modification') },
    { value: 'delete', label: t('Deletion') },
  ];
  const instanceEventTypesOptionsMap: Record<string, string> = {
    update: t('Modification'),
    delete: t('Deletion'),
  };

  const initialExistingInstanceTriggersEdges = () => {
    const existingInstanceTriggersData = usePreloadedQuery<StixCoreObjectQuickSubscriptionContentPaginationQuery>(
      stixCoreObjectQuickSubscriptionContentQuery,
      queryRef,
    );
    return existingInstanceTriggersData?.triggersKnowledge?.edges ?? [];
  };
  const [existingInstanceTriggersEdges, setExistingInstanceTriggersEdges] = useState(initialExistingInstanceTriggersEdges());

  const triggerUpdate = existingInstanceTriggersEdges.length > 0;

  const [commitAddTrigger] = useMutation<TriggerLiveCreationKnowledgeMutation>(
    triggerLiveKnowledgeCreationMutation,
  );
  const [commitFieldPatch] = useMutation(triggerMutationFieldPatch);
  const [commitDeleteTrigger] = useMutation(TriggerPopoverDeletionMutation);

  const searchInstanceTriggers = () => {
    fetchQuery(stixCoreObjectQuickSubscriptionContentQuery, paginationOptions)
      .toPromise()
      .then((data) => {
        setExistingInstanceTriggersEdges((data as StixCoreObjectQuickSubscriptionContentPaginationQuery$data)?.triggersKnowledge?.edges ?? []);
      });
  };

  const handleOpen = () => {
    searchInstanceTriggers();
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleToggleLine = () => {
    setExpandedLines(!expandedLines);
  };

  const liveTriggerValidation = () => Yup.object().shape({
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    event_types: Yup.array()
      .min(1, t('Minimum one event type'))
      .required(t('This field is required')),
    outcomes: Yup.array()
      .required(t('This field is required')),
  });

  const createInstanceTrigger = () => {
    const finalValues: TriggerLiveAddInput = {
      name: instanceName,
      description: '',
      event_types: ['update', 'delete'],
      outcomes: ['f4ee7b33-006a-4b0d-b57d-411ad288653d', '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'],
      instance_trigger: true,
      filters: JSON.stringify({
        elementId: [{
          id: instanceId,
          value: instanceName ?? '',
        }],
      }),
    };
    commitAddTrigger({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_triggers', paginationOptions, 'triggerLiveAdd');
      },
      onCompleted: () => {
        searchInstanceTriggers();
        MESSAGING$.notifySuccess('Instance trigger successfully created. You can click again on the bell to edit the options.');
      },
    });
  };

  const onSubmitUpdate: FormikConfig<InstanceTriggerEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
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
        key: 'outcomes',
        value: uniq(values.outcomes.map((n) => n.value)),
      },
    ];
    commitFieldPatch({
      variables: {
        id: values.id,
        input: finalValues,
      },
      onCompleted: () => {
        searchInstanceTriggers();
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
        deleteNode(store, 'Pagination_triggers', paginationOptions, triggerIdToDelete);
      },
      onCompleted: () => {
        searchInstanceTriggers();
        setDeleting(false);
        handleClose();
      },
    });
  };

  const submitRemove = (triggerIdToUpdate: string, filters: string | null) => {
    setDeleting(true);
    const newInstanceFilters = JSON.parse(filters ?? '').elementId.filter((f: { id: string, value: string }) => f.id !== instanceId);
    commitFieldPatch({
      variables: {
        id: triggerIdToUpdate,
        input: [
          {
            key: 'filters',
            value: JSON.stringify({ elementId: newInstanceFilters }),
          },
        ],
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_triggers', paginationOptions, triggerIdToUpdate);
      },
      onCompleted: () => {
        searchInstanceTriggers();
        setDeleting(false);
        handleClose();
      },
    });
  };

  const updateInstanceTriggerContent = (instanceTrigger: InstanceTriggerEditionFormValues, firstTrigger: boolean, multipleInstanceTrigger: boolean) => {
    return (
      <div key={instanceTrigger.id} className={firstTrigger ? classes.container : classes.subcontainer}>
        <Formik
          initialValues={instanceTrigger}
          validationSchema={liveTriggerValidation}
          onSubmit={onSubmitUpdate}
        >
          {({
            submitForm,
            isSubmitting,
            values,
            setFieldValue,
          }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
              />
              <Field
                component={AutocompleteField}
                name="outcomes"
                style={fieldSpacingContainerStyle}
                multiple={true}
                textfieldprops={{
                  variant: 'standard',
                  label: t('Notification'),
                }}
                options={outcomesOptions}
                onChange={setFieldValue}
                renderOption={(
                  props: React.HTMLAttributes<HTMLLIElement>,
                  option: { value: string, label: string },
                ) => (
                  <MenuItem value={option.value} {...props}>
                    <Checkbox
                      checked={values.outcomes.map((n) => n.value).includes(option.value)}
                    />
                    <ListItemText
                      primary={option.label}
                    />
                  </MenuItem>
                )}
              />
              <Field
                component={AutocompleteField}
                name="event_types"
                style={fieldSpacingContainerStyle}
                multiple={true}
                textfieldprops={{
                  variant: 'standard',
                  label: t('Triggering on'),
                }}
                options={instanceEventTypesOptions}
                onChange={setFieldValue}
                renderOption={(
                  props: React.HTMLAttributes<HTMLLIElement>,
                  option: { value: string, label: string },
                ) => (
                  <MenuItem value={option.value} {...props}>
                    <Checkbox checked={values.event_types.map((n) => n.value).includes(option.value)} />
                    <ListItemText primary={option.label} />
                  </MenuItem>
                )}
              />
              {multipleInstanceTrigger
                && <div style={{ ...fieldSpacingContainerStyle }}>
                  <FilterIconButton
                    filters={JSON.parse(instanceTrigger.filters ?? '[]')}
                    classNameNumber={3}
                    styleNumber={3}
                    redirection
                    resolvedInstanceFilters={instanceTrigger.resolved_instance_filters ?? []}
                  />
                </div>
              }
              <div className={classes.buttons} style={{ marginTop: firstTrigger ? 20 : 40 }}>
                <Button
                  variant="contained"
                  onClick={multipleInstanceTrigger ? () => submitRemove(values.id, values.filters) : () => submitDelete(values.id)}
                  disabled={deleting}
                  classes={{ root: classes.deleteButton }}
                >
                  {multipleInstanceTrigger ? t('Remove') : t('Delete')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.updateButton }}
                >
                  {t('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    );
  };

  const isInstanceTriggerOnMultipleInstances = (triggerValue: InstanceTriggerEditionFormValues) => {
    return triggerValue.filters && JSON.parse(triggerValue.filters).elementId.length > 1;
  };

  const updateInstanceTrigger = () => {
    const triggerValues = existingInstanceTriggersEdges
      .filter((l) => l)
      .map((n) => ({
        ...pick(['id', 'name', 'description', 'filters', 'resolved_instance_filters'], n?.node),
        outcomes: convertOutcomes(n?.node, outcomesOptionsMap),
        event_types: convertEventTypes(n?.node, instanceEventTypesOptionsMap),
      })) as InstanceTriggerEditionFormValues[];
    const uniqInstanceTriggers = triggerValues
      .filter((n) => !isInstanceTriggerOnMultipleInstances(n))
      .map((n) => ({ values: n, multiple: false }));
    const multipleInstanceTriggers = triggerValues
      .filter((n) => isInstanceTriggerOnMultipleInstances(n))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((n) => ({ values: n, multiple: true }));
    const sortedTriggersToDisplay = uniqInstanceTriggers.concat(multipleInstanceTriggers);
    const firstInstanceTriggerToDisplay = sortedTriggersToDisplay[0];
    const otherInstanceTriggersToDisplay = sortedTriggersToDisplay.slice(1); // the other instance triggers
    return (
      <Drawer
        disableRestoreFocus={true}
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
          <Typography variant="h6">{t('Update instance triggers')}</Typography>
        </div>
        <Alert severity="info" style={{ margin: '15px 15px 0 15px' }}>
          {t(instanceTriggerDescription)}
        </Alert>
        <div>
          {updateInstanceTriggerContent(firstInstanceTriggerToDisplay.values, true, firstInstanceTriggerToDisplay.multiple)}
        </div>
        {otherInstanceTriggersToDisplay.length > 0
          && <List>
            <ListItem
              button={true}
              divider={true}
              classes={{ root: classes.nested }}
              onClick={handleToggleLine}
            >
              <ListItemText primary={`${otherInstanceTriggersToDisplay.length} ${t('other trigger(s) related to this entity')}`} />
              <ListItemSecondaryAction>
                <IconButton
                  onClick={handleToggleLine}
                  aria-haspopup="true"
                  size="large"
                >
                  {expandedLines ? (
                    <ExpandLess />
                  ) : (
                    <ExpandMore />
                  )}
                </IconButton>
              </ListItemSecondaryAction>
            </ListItem>
            <Collapse
              in={expandedLines}
            >
              {otherInstanceTriggersToDisplay.map((instanceTrigger) => updateInstanceTriggerContent(instanceTrigger.values, false, instanceTrigger.multiple))}
            </Collapse>
          </List>
        }
      </Drawer>
    );
  };
  return (
    <div>
      <Tooltip title={t('Instance trigger quick subscription')}>
        <ToggleButton
          onClick={triggerUpdate ? handleOpen : createInstanceTrigger}
          value="quick-subscription"
          size="small"
          style={{ marginRight: 3 }}
        >
          <NotificationsOutlined
            fontSize="small"
            color={triggerUpdate ? 'secondary' : 'primary'}
          />
        </ToggleButton>
      </Tooltip>
      {triggerUpdate && updateInstanceTrigger()}
    </div>
  );
};

export default StixCoreObjectQuickSubscriptionContent;
