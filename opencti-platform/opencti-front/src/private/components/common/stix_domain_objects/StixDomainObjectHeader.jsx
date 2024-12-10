import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import { Add, Close, Delete } from '@mui/icons-material';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import { DialogTitle } from '@mui/material';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { stixCoreObjectQuickSubscriptionContentQuery } from '../stix_core_objects/stixCoreObjectTriggersUtils';
import StixCoreObjectAskAI from '../stix_core_objects/StixCoreObjectAskAI';
import StixCoreObjectSubscribers from '../stix_core_objects/StixCoreObjectSubscribers';
import StixCoreObjectFileExport from '../stix_core_objects/StixCoreObjectFileExport';
import StixCoreObjectContainer from '../stix_core_objects/StixCoreObjectContainer';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNGETEXPORT_KNASKEXPORT, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import CommitMessage from '../form/CommitMessage';
import StixCoreObjectSharing from '../stix_core_objects/StixCoreObjectSharing';
import { truncate } from '../../../../utils/String';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import StixCoreObjectQuickSubscription from '../stix_core_objects/StixCoreObjectQuickSubscription';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import Transition from '../../../../components/Transition';
import StixCoreObjectEnrichment from '../stix_core_objects/StixCoreObjectEnrichment';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  alias: {
    margin: '4px 7px 0 0',
    fontSize: 12,
    lineHeight: '12px',
    height: 28,
  },
  aliasesInput: {
    margin: '4px 15px 0 10px',
    float: 'left',
  },
  actionButtons: {
    display: 'flex',
  },
}));

export const stixDomainObjectMutation = graphql`
  mutation StixDomainObjectHeaderFieldMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        x_opencti_stix_ids
        ... on AttackPattern {
          aliases
        }
        ... on Campaign {
          aliases
        }
        ... on CourseOfAction {
          x_opencti_aliases
        }
        ... on Individual {
          x_opencti_aliases
        }
        ... on Organization {
          x_opencti_aliases
        }
        ... on Sector {
          x_opencti_aliases
        }
        ... on System {
          x_opencti_aliases
        }
        ... on Infrastructure {
          aliases
        }
        ... on IntrusionSet {
          aliases
        }
        ... on Position {
          x_opencti_aliases
        }
        ... on City {
          x_opencti_aliases
        }
        ... on AdministrativeArea {
          x_opencti_aliases
        }
        ... on Country {
          x_opencti_aliases
        }
        ... on Region {
          x_opencti_aliases
        }
        ... on Malware {
          aliases
        }
        ... on ThreatActor {
          aliases
        }
        ... on Tool {
          aliases
        }
        ... on Channel {
          aliases
        }
        ... on Event {
          aliases
        }
        ... on Narrative {
          aliases
        }
        ... on Language {
          aliases
        }
        ... on Incident {
          aliases
          objectAssignee {
            id
            name
            entity_type
          }
          objectParticipant {
            id
            name
            entity_type
          }
        }
        ... on Vulnerability {
          x_opencti_aliases
        }
        ... on DataComponent {
          aliases
        }
        ... on DataSource {
          aliases
        }
        ... on Report {
          objectAssignee {
            id
            name
            entity_type
          }
          objectParticipant {
            id
            name
            entity_type
          }
        }
        ... on MalwareAnalysis {
          objectAssignee {
            id
            name
            entity_type
          }
        }
        ... on CaseIncident {
          objectAssignee {
            id
            name
            entity_type
          }
          objectParticipant {
            id
            name
            entity_type
          }
        }
        ... on CaseRfi {
          objectAssignee {
            id
            name
            entity_type
          }
          objectParticipant {
            id
            name
            entity_type
          }
        }
        ... on CaseRft {
          objectAssignee {
            id
            name
            entity_type
          }
          objectParticipant {
            id
            name
            entity_type
          }
        }
        ... on Task {
          objectAssignee {
            id
            name
            entity_type
          }
          objectParticipant {
            id
            name
            entity_type
          }
        }
        ... on Feedback {
          objectAssignee {
            id
            name
            entity_type
          }
        }
      }
    }
  }
`;

const aliasValidation = (t) => Yup.object().shape({
  references: Yup.array().required(t('This field is required')),
});

const StixDomainObjectHeader = (props) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const {
    stixDomainObject,
    isOpenctiAlias,
    PopoverComponent,
    EditComponent,
    viewAs,
    onViewAs,
    disablePopover,
    disableSharing,
    noAliases,
    entityType, // Should migrate all the parent component to call the useIsEnforceReference as the top
    enableQuickSubscription,
    enableAskAi,
    enableEnricher,
  } = props;
  const openAliasesCreate = false;
  const [openAlias, setOpenAlias] = useState(false);
  const [openAliases, setOpenAliases] = useState(false);
  const [openCommitCreate, setOpenCommitCreate] = useState(false);
  const [openCommitDelete, setOpenCommitDelete] = useState(false);
  const [newAlias, setNewAlias] = useState('');
  const [aliasToDelete, setAliasToDelete] = useState(null);
  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isKnowledgeEnricher = useGranted([KNOWLEDGE_KNENRICHMENT]);
  let type = 'unsupported';
  const isThreat = ['Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set', 'Campaign', 'Incident', 'Malware', 'Tool'].includes(stixDomainObject.entity_type);
  const isVictim = ['Sector', 'Organization', 'System', 'Individual', 'Region', 'Country', 'Administrative-Area', 'City', 'Position'].includes(stixDomainObject.entity_type);
  if (isThreat) {
    type = 'threat';
  } else if (isVictim) {
    type = 'victim';
  }
  const handleToggleOpenAliases = () => {
    setOpenAliases(!openAliases);
  };

  const handleToggleCreateAlias = () => {
    setOpenAlias(!openAlias);
  };

  const handleOpenCommitCreate = () => {
    setOpenCommitCreate(true);
  };

  const handleCloseCommitCreate = () => {
    setOpenCommitCreate(false);
  };

  const handleOpenCommitDelete = (label) => {
    setOpenCommitDelete(true);
    setAliasToDelete(label);
  };

  const handleCloseCommitDelete = () => {
    setOpenCommitDelete(false);
  };

  const handleChangeNewAlias = (name, value) => {
    setNewAlias(value);
  };

  const getCurrentAliases = () => {
    return isOpenctiAlias
      ? stixDomainObject.x_opencti_aliases
      : stixDomainObject.aliases;
  };

  const onSubmitCreateAlias = (values, { resetForm, setSubmitting }) => {
    const currentAliases = getCurrentAliases();
    const normalizeNameEntity = (stixDomainObject.name).toLowerCase().trim();
    const normalizeNewAlias = newAlias.toLowerCase().trim();
    if (normalizeNameEntity === normalizeNewAlias) {
      setOpenAlias(false);
      setOpenCommitCreate(false);
      setNewAlias('');
      resetForm();
      MESSAGING$.notifyError('You can\'t add the same alias as the name');
      return;
    }
    if (
      (currentAliases === null || !currentAliases.includes(newAlias))
      && newAlias !== ''
    ) {
      commitMutation({
        mutation: stixDomainObjectMutation,
        variables: {
          id: stixDomainObject.id,
          input: {
            key: isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
            value: R.append(newAlias, currentAliases),
          },
          commitMessage: values.message,
          references: R.pluck('value', values.references || []),
        },
        setSubmitting,
        onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The alias has been added')),
      });
    }
    setOpenAlias(false);
    setOpenCommitCreate(false);
    setNewAlias('');
    resetForm();
  };

  const deleteAlias = (alias, data = {}) => {
    const currentAliases = getCurrentAliases();
    const aliases = R.filter((a) => a !== alias, currentAliases);
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObject.id,
        input: {
          key: isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
          value: aliases,
        },
        commitMessage: data.message,
        references: R.pluck('value', data.references || []),
      },
      onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The alias has been removed')),
    });
    setOpenCommitDelete(false);
  };

  const onSubmitDeleteAlias = (data, { resetForm }) => {
    deleteAlias(aliasToDelete, data);
    setOpenCommitDelete(false);
    setAliasToDelete(null);
    resetForm();
  };

  const aliases = R.propOr(
    [],
    isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
    stixDomainObject,
  );
  const enableReferences = useIsEnforceReference(entityType);

  const triggersPaginationOptions = {
    includeAuthorities: true,
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        {
          key: ['filters'],
          values: [stixDomainObject.id],
          operator: 'match',
          mode: 'or',
        },
        {
          key: ['instance_trigger'],
          values: ['true'],
          operator: 'eq',
          mode: 'or',
        },
      ],
    },
  };
  const triggerData = useLazyLoadQuery(stixCoreObjectQuickSubscriptionContentQuery, { first: 20, ...triggersPaginationOptions });

  return (
    <React.Suspense fallback={<span />}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: theme.spacing(1) }}>
        <div style={{ display: 'flex', gap: theme.spacing(2) }}>
          <Tooltip title={getMainRepresentative(stixDomainObject)}>
            <Typography
              variant="h1"
              sx={{
                margin: 0,
                lineHeight: 'unset',
              }}
            >
              {truncate(getMainRepresentative(stixDomainObject), 80)}
            </Typography>
          </Tooltip>
          {typeof onViewAs === 'function' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.5) }}>
              <InputLabel>
                {t_i18n('Display as')}
              </InputLabel>
              <FormControl
                variant="outlined"
              >
                <Select
                  size="small"
                  name="view-as"
                  value={viewAs}
                  onChange={onViewAs}
                  inputProps={{
                    name: 'view-as',
                    id: 'view-as',
                  }}
                  variant="outlined"
                >
                  <MenuItem value="knowledge">{t_i18n('Knowledge entity')}</MenuItem>
                  <MenuItem value="author">{t_i18n('Author')}</MenuItem>
                </Select>
              </FormControl>
            </div>
          )}
          <div style={{ display: 'flex' }}>
            {(!noAliases && aliases.length > 0) && (
              <div>
                {R.take(5, aliases).map(
                  (label) => label.length > 0 && (
                    <Security
                      needs={[KNOWLEDGE_KNUPDATE]}
                      key={label}
                      placeholder={
                        <Tooltip title={label}>
                          <Chip
                            classes={{ root: classes.alias }}
                            label={truncate(label, 40)}
                          />
                        </Tooltip>
                      }
                    >
                      <Tooltip title={label}>
                        <Chip
                          classes={{ root: classes.alias }}
                          label={truncate(label, 40)}
                          onDelete={
                            enableReferences
                              ? () => handleOpenCommitDelete(label)
                              : () => deleteAlias(label)
                          }
                        />
                      </Tooltip>
                    </Security>
                  ),
                )}
              </div>
            )}
            {!noAliases && (
              <Slide
                direction="right"
                in={openAlias}
                mountOnEnter={true}
                unmountOnExit={true}
              >
                <div>
                  <Formik
                    initialValues={{ new_alias: '' }}
                    onSubmit={onSubmitCreateAlias}
                    validationSchema={enableReferences ? aliasValidation(t_i18n) : null}
                  >
                    {({ submitForm, isSubmitting, setFieldValue, values }) => (
                      <Form>
                        <Field
                          component={TextField}
                          variant="standard"
                          name="new_alias"
                          autoFocus={true}
                          placeholder={t_i18n('New alias')}
                          className={classes.aliasesInput}
                          onChange={handleChangeNewAlias}
                          value={newAlias}
                          onKeyDown={(e) => {
                            if (e.keyCode === 13) {
                              if (enableReferences && !openCommitCreate) {
                                return handleOpenCommitCreate();
                              }
                              return submitForm();
                            }
                            return true;
                          }}
                        />
                        {enableReferences && (
                          <CommitMessage
                            handleClose={openCommitCreate}
                            open={openCommitCreate}
                            submitForm={submitForm}
                            disabled={isSubmitting}
                            setFieldValue={setFieldValue}
                            values={values.references}
                            id={stixDomainObject.id}
                          />
                        )}
                      </Form>
                    )}
                  </Formik>
                </div>
              </Slide>
            )}
            {!noAliases && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                {aliases.length > 5 ? (
                  <IconButton
                    color="primary"
                    aria-label="More"
                    onClick={handleToggleOpenAliases}
                    size="small"
                  >
                    <DotsHorizontalCircleOutline fontSize="small" />
                  </IconButton>
                ) : (
                  <IconButton
                    color="primary"
                    aria-label="Alias"
                    onClick={handleToggleCreateAlias}
                    size="small"
                  >
                    {openAlias ? (
                      <Close fontSize="small" />
                    ) : (
                      <Add fontSize="small" />
                    )}
                  </IconButton>
                )}
              </Security>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <div className={classes.actionButtons}>
            {enableQuickSubscription && (
              <StixCoreObjectSubscribers triggerData={triggerData} />
            )}
            {disableSharing !== true && (
              <StixCoreObjectSharing
                elementId={stixDomainObject.id}
                variant="header"
              />
            )}
            <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
              <StixCoreObjectFileExport
                id={stixDomainObject.id}
                type={entityType}
              />
            </Security>
            {isKnowledgeUpdater && (
              <StixCoreObjectContainer elementId={stixDomainObject.id} />
            )}
            {enableQuickSubscription && (
              <StixCoreObjectQuickSubscription
                instanceId={stixDomainObject.id}
                instanceName={getMainRepresentative(stixDomainObject)}
                paginationOptions={triggersPaginationOptions}
                triggerData={triggerData}
              />
            )}
            {enableAskAi && (
              <StixCoreObjectAskAI
                instanceId={stixDomainObject.id}
                instanceType={stixDomainObject.entity_type}
                instanceName={getMainRepresentative(stixDomainObject)}
                instanceMarkings={stixDomainObject.objectMarking.map(({ id }) => id) ?? []}
                type={type}
              />
            )}
            {(enableEnricher && isKnowledgeEnricher) && (
              <StixCoreObjectEnrichment stixCoreObjectId={stixDomainObject.id} />
            )}
            {isKnowledgeUpdater && (
              <div className={classes.popover}>
                {/* TODO remove this when all components are pure function without compose() */}
                {!React.isValidElement(PopoverComponent) ? (
                  <PopoverComponent
                    disabled={disablePopover}
                    id={stixDomainObject.id}
                  />
                ) : (
                  React.cloneElement(PopoverComponent, {
                    id: stixDomainObject.id,
                    disabled: disablePopover,
                  })
                )}
              </div>
            )}
            {EditComponent}
          </div>
        </div>
      </div>
      {!noAliases && (
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={openAliases}
          TransitionComponent={Transition}
          onClose={handleToggleOpenAliases}
          fullWidth={true}
        >
          <DialogTitle>
            {t_i18n('Entity aliases')}
            <Formik
              initialValues={{ new_alias: '' }}
              onSubmit={onSubmitCreateAlias}
              validationSchema={enableReferences ? aliasValidation(t_i18n) : null}
            >
              {({ submitForm, isSubmitting, setFieldValue, values }) => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_alias"
                    autoFocus={true}
                    placeholder={t_i18n('New alias')}
                    className={classes.aliasesInput}
                    onChange={handleChangeNewAlias}
                    value={newAlias}
                    onKeyDown={(e) => {
                      if (e.keyCode === 13) {
                        if (enableReferences) {
                          return handleOpenCommitCreate();
                        }
                        return submitForm();
                      }
                      return true;
                    }}
                  />
                  {enableReferences && (
                    <CommitMessage
                      handleClose={handleCloseCommitCreate}
                      open={openCommitCreate}
                      submitForm={submitForm}
                      disabled={isSubmitting}
                      setFieldValue={setFieldValue}
                      values={values.references}
                      id={stixDomainObject.id}
                    />
                  )}
                </Form>
              )}
            </Formik>
          </DialogTitle>
          <DialogContent dividers={true}>
            <List>
              {R.propOr(
                [],
                isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
                stixDomainObject,
              ).map(
                (label) => label.length > 0 && (
                  <ListItem key={label} disableGutters={true} dense={true}>
                    <ListItemText primary={label} />
                    <ListItemSecondaryAction>
                      <IconButton
                        edge="end"
                        aria-label="delete"
                        onClick={
                          enableReferences
                            ? () => handleOpenCommitDelete(label)
                            : () => deleteAlias(label)
                        }
                        size="large"
                      >
                        <Delete />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ),
              )}
            </List>
            <div
              style={{
                display: openAliasesCreate ? 'block' : 'none',
              }}
            >
              <Formik
                initialValues={{ new_alias: '' }}
                onSubmit={onSubmitCreateAlias}
                validationSchema={enableReferences ? aliasValidation(t_i18n) : null}
              >
                {({ submitForm, isSubmitting, setFieldValue, values }) => (
                  <Form>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="new_alias"
                      autoFocus={true}
                      fullWidth={true}
                      placeholder={t_i18n('New aliases')}
                      className={classes.aliasesInput}
                      onChange={handleChangeNewAlias}
                      value={newAlias}
                      onKeyDown={(e) => {
                        if (e.keyCode === 13) {
                          if (enableReferences && !openCommitCreate) {
                            return handleOpenCommitCreate();
                          }
                          return submitForm();
                        }
                        return true;
                      }}
                    />
                    {enableReferences && (
                      <CommitMessage
                        handleClose={handleCloseCommitCreate}
                        open={openCommitCreate}
                        submitForm={submitForm}
                        disabled={isSubmitting}
                        setFieldValue={setFieldValue}
                        values={values.references}
                        id={stixDomainObject.id}
                      />
                    )}
                  </Form>
                )}
              </Formik>
            </div>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleToggleOpenAliases} color="primary">
              {t_i18n('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
      {enableReferences && (
        <Formik
          initialValues={{}}
          onSubmit={onSubmitDeleteAlias}
          validationSchema={aliasValidation(t_i18n)}
        >
          {({ submitForm, isSubmitting, setFieldValue, values }) => (
            <Form style={{ float: 'right' }}>
              <CommitMessage
                handleClose={handleCloseCommitDelete}
                open={openCommitDelete}
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                values={values.references}
                id={stixDomainObject.id}
              />
            </Form>
          )}
        </Formik>
      )}
    </React.Suspense>
  );
};

export default StixDomainObjectHeader;
