import { ExpandLess, ExpandMore, NotificationsOutlined } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Collapse from '@mui/material/Collapse';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { makeStyles } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { pick, uniq } from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import Drawer from '@components/common/drawer/Drawer';
import AutocompleteField from '../../../../components/AutocompleteField';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { convertEventTypes, convertNotifiers, instanceEventTypesOptions } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { deleteNode, insertNode } from '../../../../utils/store';
import { TriggerLine_node$data } from '../../profile/triggers/__generated__/TriggerLine_node.graphql';
import { TriggerLiveAddInput, TriggerLiveCreationKnowledgeMutation } from '../../profile/triggers/__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { triggerMutationFieldPatch } from '../../profile/triggers/TriggerEditionOverview';
import { instanceTriggerDescription, triggerLiveKnowledgeCreationMutation } from '../../profile/triggers/TriggerLiveCreation';
import { TriggerPopoverDeletionMutation } from '../../profile/triggers/TriggerPopover';
import NotifierField from '../form/NotifierField';
import { Option } from '../form/ReferenceField';
import { StixCoreObjectQuickSubscriptionContentPaginationQuery, StixCoreObjectQuickSubscriptionContentPaginationQuery$data, StixCoreObjectQuickSubscriptionContentPaginationQuery$variables } from './__generated__/StixCoreObjectQuickSubscriptionContentPaginationQuery.graphql';

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
          notifiers {
            id
            name
          }
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
  event_types: readonly Option[];
  notifiers: readonly Option[];
  filters: string | null,
  resolved_instance_filters?: TriggerLine_node$data['resolved_instance_filters'],
}

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
    notifiers: Yup.array()
      .required(t('This field is required')),
  });

  const createInstanceTrigger = () => {
    const finalValues: TriggerLiveAddInput = {
      name: instanceName,
      description: '',
      event_types: ['update', 'delete'],
      notifiers: ['f4ee7b33-006a-4b0d-b57d-411ad288653d', '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'],
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
        insertNode(store, 'Pagination_triggersKnowledge', paginationOptions, 'triggerKnowledgeLiveAdd');
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
        deleteNode(store, 'Pagination_triggersKnowledge', paginationOptions, triggerIdToDelete);
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
        deleteNode(store, 'Pagination_triggersKnowledge', paginationOptions, triggerIdToUpdate);
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
              <NotifierField
                name="notifiers"
                onChange={setFieldValue}
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
    const sortedTriggersToDisplay = uniqInstanceTriggers.concat(multipleInstanceTriggers);
    const firstInstanceTriggerToDisplay = sortedTriggersToDisplay[0];
    const otherInstanceTriggersToDisplay = sortedTriggersToDisplay.slice(1); // the other instance triggers
    return (
      <Drawer
        title={t('Update instance triggers')}
        open={open}
        onClose={handleClose}
      >
        <>
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
        </>
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
