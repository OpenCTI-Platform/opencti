import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { graphql } from 'react-relay';
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
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
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
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectEnrichment from '../stix_core_objects/StixCoreObjectEnrichment';
import CommitMessage from '../form/CommitMessage';
import StixCoreObjectSharing from '../stix_core_objects/StixCoreObjectSharing';
import { truncate } from '../../../../utils/String';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import StixCoreObjectQuickSubscription from '../stix_core_objects/StixCoreObjectQuickSubscription';
import { defaultValue } from '../../../../utils/Graph';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  aliases: {
    float: 'left',
    marginTop: -4,
  },
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
  viewAsField: {
    marginTop: -4,
    float: 'left',
  },
  viewAsFieldLabel: {
    margin: '4px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
  actions: {
    margin: '-6px 0 0 0',
    float: 'right',
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
        ... on ThreatActorGroup {
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
      }
    }
  }
`;

const aliasValidation = (t) => Yup.object().shape({
  references: Yup.array().required(t('This field is required')),
});

const StixDomainObjectHeader = (props) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const {
    stixDomainObject,
    isOpenctiAlias,
    PopoverComponent,
    viewAs,
    onViewAs,
    disablePopover,
    disableSharing,
    noAliases,
    entityType, // Should migrate all the parent component to call the useIsEnforceReference as the top
    enableQuickSubscription,
  } = props;

  const openAliasesCreate = false;
  const [openAlias, setOpenAlias] = useState(false);
  const [openAliases, setOpenAliases] = useState(false);
  const [openCommitCreate, setOpenCommitCreate] = useState(false);
  const [openCommitDelete, setOpenCommitDelete] = useState(false);
  const [newAlias, setNewAlias] = useState('');
  const [aliasToDelete, setAliasToDelete] = useState(null);

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
        onCompleted: () => MESSAGING$.notifySuccess(t('The alias has been added')),
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
      onCompleted: () => MESSAGING$.notifySuccess(t('The alias has been removed')),
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
  return (
    <div>
      <Tooltip title={defaultValue(stixDomainObject)}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(defaultValue(stixDomainObject), 80)}
        </Typography>
      </Tooltip>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
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
      </Security>
      {typeof onViewAs === 'function' && (
        <div>
          <InputLabel classes={{ root: classes.viewAsFieldLabel }}>
            {t('Display as')}
          </InputLabel>
          <FormControl classes={{ root: classes.viewAsField }}>
            <Select
              size="small"
              name="view-as"
              value={viewAs}
              onChange={onViewAs}
              inputProps={{
                name: 'view-as',
                id: 'view-as',
              }}
            >
              <MenuItem value="knowledge">{t('Knowledge entity')}</MenuItem>
              <MenuItem value="author">{t('Author')}</MenuItem>
            </Select>
          </FormControl>
        </div>
      )}
      {!noAliases && (
        <div
          className={classes.aliases}
          style={{ marginLeft: typeof onViewAs === 'function' ? 10 : 0 }}
        >
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
          <div style={{ float: 'left', marginTop: -5 }}>
            <Formik
              initialValues={{ new_alias: '' }}
              onSubmit={onSubmitCreateAlias}
              validationSchema={enableReferences ? aliasValidation(t) : null}
            >
              {({ submitForm, isSubmitting, setFieldValue, values }) => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_alias"
                    autoFocus={true}
                    placeholder={t('New alias')}
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
              style={{ float: 'left', marginTop: -8 }}
              color="primary"
              aria-label="More"
              onClick={handleToggleOpenAliases}
              size="large"
            >
              <DotsHorizontalCircleOutline fontSize="small" />
            </IconButton>
          ) : (
            <IconButton
              style={{ float: 'left', marginTop: -8 }}
              color={openAlias ? 'primary' : 'secondary'}
              aria-label="Alias"
              onClick={handleToggleCreateAlias}
              size="large"
            >
              {openAlias ? (
                <Close fontSize="small" color="primary" />
              ) : (
                <Add fontSize="small" />
              )}
            </IconButton>
          )}
        </Security>
      )}
      <div className={classes.actions}>
        <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
          {disableSharing !== true && (
            <StixCoreObjectSharing
              elementId={stixDomainObject.id}
              variant="header"
            />
          )}
          {enableQuickSubscription && (
            <StixCoreObjectQuickSubscription
              instanceId={stixDomainObject.id}
              instanceName={defaultValue(stixDomainObject)}
            />
          )}
          <StixCoreObjectEnrichment stixCoreObjectId={stixDomainObject.id} />
        </ToggleButtonGroup>
      </div>
      <div className="clearfix" />
      {!noAliases && (
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={openAliases}
          TransitionComponent={Transition}
          onClose={handleToggleOpenAliases}
          fullWidth={true}
        >
          <DialogTitle>
            {t('Entity aliases')}
            <Formik
              initialValues={{ new_alias: '' }}
              onSubmit={onSubmitCreateAlias}
              validationSchema={enableReferences ? aliasValidation(t) : null}
            >
              {({ submitForm, isSubmitting, setFieldValue, values }) => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_alias"
                    autoFocus={true}
                    placeholder={t('New alias')}
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
                validationSchema={enableReferences ? aliasValidation(t) : null}
              >
                {({ submitForm, isSubmitting, setFieldValue, values }) => (
                  <Form>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="new_alias"
                      autoFocus={true}
                      fullWidth={true}
                      placeholder={t('New aliases')}
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
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
      {enableReferences && (
        <Formik
          initialValues={{}}
          onSubmit={onSubmitDeleteAlias}
          validationSchema={aliasValidation(t)}
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
    </div>
  );
};

export default StixDomainObjectHeader;
