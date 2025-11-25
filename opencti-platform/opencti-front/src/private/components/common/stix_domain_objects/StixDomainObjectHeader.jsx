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
import ListItemText from '@mui/material/ListItemText';
import { Box, DialogTitle } from '@mui/material';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import FormAuthorizedMembersDialog from '../form/FormAuthorizedMembersDialog';
import StixCoreObjectMenuItemUnderEE from '../stix_core_objects/StixCoreObjectMenuItemUnderEE';
import StixCoreObjectSharingList from '../stix_core_objects/StixCoreObjectSharingList';
import { DraftChip } from '../draft/DraftChip';
import StixCoreObjectEnrollPlaybook from '../stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectFileExportButton from '../stix_core_objects/StixCoreObjectFileExportButton';
import { stixCoreObjectQuickSubscriptionContentQuery } from '../stix_core_objects/stixCoreObjectTriggersUtils';
import StixCoreObjectSubscribers from '../stix_core_objects/StixCoreObjectSubscribers';
import StixCoreObjectFileExport from '../stix_core_objects/StixCoreObjectFileExport';
import StixCoreObjectContainer from '../stix_core_objects/StixCoreObjectContainer';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useGranted, {
  AUTOMATION,
  BYPASS,
  KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNGETEXPORT_KNASKEXPORT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS,
  KNOWLEDGE_KNUPDATE_KNORGARESTRICT,
} from '../../../../utils/hooks/useGranted';
import CommitMessage from '../form/CommitMessage';
import StixCoreObjectSharing from '../stix_core_objects/StixCoreObjectSharing';
import { truncate } from '../../../../utils/String';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import StixCoreObjectQuickSubscription from '../stix_core_objects/StixCoreObjectQuickSubscription';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import Transition from '../../../../components/Transition';
import StixCoreObjectEnrichment from '../stix_core_objects/StixCoreObjectEnrichment';
import PopoverMenu from '../../../../components/PopoverMenu';
import { resolveLink } from '../../../../utils/Entity';
import { authorizedMembersToOptions, CAN_USE_ENTITY_TYPES, useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import useHelper from '../../../../utils/hooks/useHelper';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

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
          currentUserAccessRight
          authorized_members {
            id
            member_id
            name
            entity_type
            access_right
            groups_restriction {
              id
              name
            }
          }
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

const stixDomainObjectHeaderEditAuthorizedMembersMutation = graphql`
  mutation  StixDomainObjectHeaderEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    stixDomainObjectEdit(id: $id) {
      editAuthorizedMembers(input: $input) {
        ... on Organization {
          authorized_members {
              id
              member_id
              name
              entity_type
              access_right
              groups_restriction {
                  id
                  name
              }
          }
        }
      }
    }
  }
`;

const StixDomainObjectHeader = (props) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const {
    stixDomainObject,
    isOpenctiAlias,
    EditComponent,
    DeleteComponent,
    RelateComponent,
    viewAs,
    onViewAs,
    disableSharing,
    noAliases,
    entityType, // Should migrate all the parent component to call the useIsEnforceReference as the top
    enableQuickSubscription,
    enableEnricher,
    enableEnrollPlaybook,
    enableAuthorizedMembers,
    redirectToContent,
  } = props;
  const currentAccessRight = useGetCurrentUserAccessRight(stixDomainObject.currentUserAccessRight);
  const enableManageAuthorizedMembers = currentAccessRight.canManage && enableAuthorizedMembers;
  const { isFeatureEnable } = useHelper();

  // Remove CRUD button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentDraftAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canEdit = !draftContext || currentDraftAccessRight.canEdit;

  const openAliasesCreate = false;
  const [openAlias, setOpenAlias] = useState(false);
  const [openAliases, setOpenAliases] = useState(false);
  const [openCommitCreate, setOpenCommitCreate] = useState(false);
  const [openCommitDelete, setOpenCommitDelete] = useState(false);
  const [openAccessRestriction, setOpenAccessRestriction] = useState(false);
  const [newAlias, setNewAlias] = useState('');
  const [aliasToDelete, setAliasToDelete] = useState(null);
  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]) && canEdit;
  const isKnowledgeEnricher = useGranted([KNOWLEDGE_KNENRICHMENT]) && canEdit;
  const isKnowledgeDeleter = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]) && canEdit;
  const isBypassEnforcedRef = useGranted([BYPASS, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);

  const [isEnrollPlaybookOpen, setEnrollPlaybookOpen] = useState(false);
  const [isSharingOpen, setIsSharingOpen] = useState(false);
  const [isEnrichmentOpen, setIsEnrichmentOpen] = useState(false);
  const navigate = useNavigate();

  const handleExportCompleted = (fileName) => {
    // navigate with fileName in query params to select the created file
    const fileParams = { currentFileId: fileName, contentSelected: false };
    const urlParams = new URLSearchParams(fileParams).toString();
    const entityLink = `${resolveLink(entityType)}/${stixDomainObject.id}`;
    const targetTab = redirectToContent ? 'content' : 'files';
    navigate(`${entityLink}/${targetTab}?${urlParams}`);
  };
  const [openDelete, setOpenDelete] = useState(false);

  const handleOpenDelete = () => setOpenDelete(true);

  const handleCloseDelete = () => setOpenDelete(false);

  const handleCloseEnrollPlaybook = () => setEnrollPlaybookOpen(false);

  const handleCloseSharing = () => setIsSharingOpen(false);

  const handleOpenEnrichment = () => setIsEnrichmentOpen(true);

  const handleCloseEnrichment = () => setIsEnrichmentOpen(false);

  const handleToggleOpenAliases = () => setOpenAliases(!openAliases);

  const handleToggleCreateAlias = () => setOpenAlias(!openAlias);

  const handleOpenCommitCreate = () => setOpenCommitCreate(true);

  const handleCloseCommitCreate = () => setOpenCommitCreate(false);

  const handleOpenCommitDelete = (label) => {
    setOpenCommitDelete(true);
    setAliasToDelete(label);
  };

  const handleCloseCommitDelete = () => setOpenCommitDelete(false);

  const handleCloseAccessRestriction = () => {
    setOpenAccessRestriction(false);
  };

  const handleChangeNewAlias = (_, value) => setNewAlias(value);

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

  let initialNumberOfButtons = 1 + (isKnowledgeUpdater ? 1 : 0) + (enableQuickSubscription ? 1 : 0);
  const displayEnrollPlaybookButton = enableEnrollPlaybook && initialNumberOfButtons < 3;
  if (displayEnrollPlaybookButton) initialNumberOfButtons += 1;
  const displaySharingButton = disableSharing !== true && initialNumberOfButtons < 3;
  const displayPopoverMenu = (disableSharing !== true && !displaySharingButton)
    || (enableEnrollPlaybook && !displayEnrollPlaybookButton)
    || (enableEnricher && isKnowledgeEnricher)
    || isKnowledgeDeleter;

  return (
    <React.Suspense fallback={<span />}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: theme.spacing(1) }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
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
          {stixDomainObject.draftVersion && (
            <DraftChip />
          )}
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
          <div style={{ display: 'flex', alignItems: 'center' }}>
            {(!noAliases && aliases.length > 0) && (
              <>
                {aliases.slice(0, 5).map(
                  (label) => label.length > 0 && (
                    <Security
                      needs={[KNOWLEDGE_KNUPDATE]}
                      key={label}
                      placeholder={
                        <Tooltip title={label}>
                          <Chip
                            sx={{
                              marginRight: '4px',
                              fontSize: 12,
                              lineHeight: '12px',
                              height: 28,
                            }}
                            label={truncate(label, 40)}
                          />
                        </Tooltip>
                      }
                    >
                      <Tooltip title={label}>
                        <Chip
                          sx={{
                            marginRight: '4px',
                            fontSize: 12,
                            lineHeight: '12px',
                            height: 28,
                          }}
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
              </>
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
                    validationSchema={enableReferences && !isBypassEnforcedRef ? aliasValidation(t_i18n) : null}
                  >
                    {({ submitForm, isSubmitting, setFieldValue, values }) => (
                      <Form>
                        <Field
                          component={TextField}
                          variant="standard"
                          name="new_alias"
                          autoFocus={true}
                          placeholder={t_i18n('New alias')}
                          sx={{
                            margin: '4px 15px 0 10px',
                            float: 'left',
                          }}
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
          <div style={{ display: 'flex' }}>
            {enableQuickSubscription && (
              <StixCoreObjectSubscribers triggerData={triggerData} />
            )}
            {disableSharing !== true && (
              <StixCoreObjectSharingList data={stixDomainObject} />
            )}
            {disableSharing !== true && (
              <StixCoreObjectSharing
                elementId={stixDomainObject.id}
                open={isSharingOpen}
                variant="header"
                handleClose={displaySharingButton ? undefined : handleCloseSharing}
              />
            )}
            <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
              <StixCoreObjectFileExport
                scoId={stixDomainObject.id}
                scoEntityType={entityType}
                OpenFormComponent={StixCoreObjectFileExportButton}
                onExportCompleted={handleExportCompleted}
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
            {(enableEnricher && isKnowledgeEnricher) && (
              <StixCoreObjectEnrichment
                onClose={handleCloseEnrichment}
                isOpen={isEnrichmentOpen}
                stixCoreObjectId={stixDomainObject.id}
              />
            )}
            {enableEnrollPlaybook && (
              <StixCoreObjectEnrollPlaybook
                open={isEnrollPlaybookOpen}
                handleClose={displayEnrollPlaybookButton ? undefined : handleCloseEnrollPlaybook}
                stixCoreObjectId={stixDomainObject.id}
              />
            )}
            {enableManageAuthorizedMembers && (
              <FormAuthorizedMembersDialog
                id={stixDomainObject.id}
                owner={stixDomainObject.creators?.[0]}
                authorizedMembers={authorizedMembersToOptions(
                  stixDomainObject.authorized_members,
                )}
                mutation={stixDomainObjectHeaderEditAuthorizedMembersMutation}
                open={openAccessRestriction}
                handleClose={handleCloseAccessRestriction}
                isCanUseEnable={CAN_USE_ENTITY_TYPES.includes(stixDomainObject.entity_type)}
                canDeactivate={true}
              />
            )}
            {displayPopoverMenu ? (
              <PopoverMenu>
                {({ closeMenu }) => (
                  <Box>
                    {disableSharing !== true && !displaySharingButton && (
                      <StixCoreObjectMenuItemUnderEE
                        setOpen={setIsSharingOpen}
                        title={t_i18n('Share with an organization')}
                        handleCloseMenu={closeMenu}
                        needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}
                      />
                    )}
                    {enableManageAuthorizedMembers && (
                      <StixCoreObjectMenuItemUnderEE
                        setOpen={setOpenAccessRestriction}
                        title={t_i18n('Manage access restriction')}
                        handleCloseMenu={closeMenu}
                        isDisabled={!enableManageAuthorizedMembers}
                        needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}
                      />
                    )}
                    {(enableEnricher && isKnowledgeEnricher) && (
                      <MenuItem onClick={() => {
                        handleOpenEnrichment();
                        closeMenu();
                      }}
                      >
                        {t_i18n('Enrichment')}
                      </MenuItem>
                    )}
                    {enableEnrollPlaybook && !displayEnrollPlaybookButton && (
                      <StixCoreObjectMenuItemUnderEE
                        title={t_i18n('Enroll in playbook')}
                        setOpen={setEnrollPlaybookOpen}
                        handleCloseMenu={closeMenu}
                        needs={[AUTOMATION]}
                        matchAll
                      />
                    )}
                    {isKnowledgeDeleter && (
                      <MenuItem onClick={() => {
                        handleOpenDelete();
                        closeMenu();
                      }}
                      >
                        {t_i18n('Delete')}
                      </MenuItem>
                    )}
                  </Box>
                )}
              </PopoverMenu>
            ) : null}
            {isFeatureEnable('FAB_RELATIONSHIP') && RelateComponent}
            {EditComponent}
            <DeleteComponent isOpen={openDelete} onClose={handleCloseDelete} />
          </div>
        </div>
      </div>
      {!noAliases && (
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={openAliases}
          slots={{ transition: Transition }}
          onClose={handleToggleOpenAliases}
          fullWidth={true}
        >
          <DialogTitle>
            {t_i18n('Entity aliases')}
            <Formik
              initialValues={{ new_alias: '' }}
              onSubmit={onSubmitCreateAlias}
              validationSchema={enableReferences && !isBypassEnforcedRef ? aliasValidation(t_i18n) : null}
            >
              {({ submitForm, isSubmitting, setFieldValue, values }) => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_alias"
                    autoFocus={true}
                    placeholder={t_i18n('New alias')}
                    sx={{
                      margin: '4px 15px 0 10px',
                      float: 'left',
                    }}
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
                  <ListItem
                    key={label}
                    disableGutters={true}
                    dense={true}
                    secondaryAction={
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
                    }
                  >
                    <ListItemText primary={label} />
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
                validationSchema={enableReferences && !isBypassEnforcedRef ? aliasValidation(t_i18n) : null}
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
                      sx={{
                        margin: '4px 15px 0 10px',
                        float: 'left',
                      }}
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
          validationSchema={!isBypassEnforcedRef && aliasValidation(t_i18n)}
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
      {disableSharing !== true && (
        <StixCoreObjectSharing
          open={isSharingOpen}
          handleClose={handleCloseSharing}
          elementId={stixDomainObject.id}
          variant="header"
        />
      )}
    </React.Suspense>
  );
};

export default StixDomainObjectHeader;
