import React, { useState } from 'react';
import * as R from 'ramda';
import fileDownload from 'js-file-download';
import { Field, Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import TextField from '@mui/material/TextField';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import Select from '@mui/material/Select';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Slide from '@mui/material/Slide';
import { AddOutlined, CloseOutlined, Delete, LockPersonOutlined, MoveToInboxOutlined } from '@mui/icons-material';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import PropTypes from 'prop-types';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import WorkspaceShareButton from './WorkspaceShareButton';
import WorkspaceDuplicationDialog from './WorkspaceDuplicationDialog';
import handleExportJson from './workspaceExportHandler';
import WorkspaceTurnToContainerDialog from './WorkspaceTurnToContainerDialog';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { nowUTC } from '../../../utils/Time';
import useGranted, { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import WorkspacePopover from './WorkspacePopover';
import ExportButtons from '../../../components/ExportButtons';
import { useFormatter } from '../../../components/i18n';
import WorkspaceManageAccessDialog from './WorkspaceManageAccessDialog';
import Transition from '../../../components/Transition';
import useHelper from '../../../utils/hooks/useHelper';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  manageAccess: {
    margin: '-8px 4px 0 0',
    float: 'right',
  },
  turnToReportOrCase: {
    margin: '-8px 4px 0 0',
    float: 'right',
  },
  export: {
    float: 'right',
    margin: '-8px 0 0 0',
    display: 'flex',
  },
  tags: {
    float: 'right',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'end',
    marginTop: '-8px',
  },
  tag: {
    marginRight: 7,
    paddingBottom: 2,
    marginBottom: 3,
    maxWidth: 180,
  },
  tagsInput: {
    margin: '4px 15px 0 10px',
    float: 'right',
  },
}));

const workspaceMutation = graphql`
  mutation WorkspaceHeaderFieldMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      tags
    }
  }
`;

const workspaceHeaderToStixReportBundleQuery = graphql`
  query WorkspaceHeaderToStixReportBundleQuery($id: String!) {
    workspace(id: $id) {
      toStixReportBundle
    }
  }
`;

const WorkspaceHeader = ({
  workspace,
  config,
  variant,
  adjust,
  handleDateChange,
  widgetActions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const openTagsCreate = false;
  const [openTag, setOpenTag] = useState(false);
  const [newTag, setNewTag] = useState('');
  const [openTags, setOpenTags] = useState(false);
  const { canManage, canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleCloseDuplicate = () => setDisplayDuplicate(false);
  const [duplicating, setDuplicating] = useState(false);
  const tags = workspace.tags ? workspace.tags : [];
  const { isFeatureEnable } = useHelper();

  const handleOpenTag = () => {
    setOpenTag(!openTag);
  };

  const handleToggleOpenTags = () => {
    setOpenTags(!openTags);
  };
  const handleChangeNewTags = (event) => {
    const { value } = event.target;
    setNewTag(value);
  };
  const onSubmitCreateTag = (data, { resetForm, setSubmitting }) => {
    if (
      (tags === null || !tags.includes(newTag))
      && newTag !== ''
    ) {
      commitMutation({
        mutation: workspaceMutation,
        variables: {
          id: workspace.id,
          input: {
            key: 'tags',
            value: [...tags, newTag],
          },
        },
        setSubmitting,
        onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The tag has been added')),
      });
    }
    setOpenTag(false);
    setNewTag('');
    resetForm();
  };
  const deleteTag = (tag) => {
    const filteredTags = tags.filter((a) => a !== tag);
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        id: workspace.id,
        input: {
          key: 'tags',
          value: filteredTags,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The tag has been removed')),
    });
  };
  const { relativeDate } = config ?? {};
  const [displayManageAccess, setDisplayManageAccess] = useState(false);
  const handleOpenManageAccess = () => setDisplayManageAccess(true);
  const handleCloseManageAccess = () => setDisplayManageAccess(false);
  const handleDownloadAsStixReport = () => {
    fetchQuery(workspaceHeaderToStixReportBundleQuery, { id: workspace.id })
      .toPromise()
      .then((data) => {
        const toStixBundleData = data?.workspace?.toStixReportBundle;
        if (toStixBundleData) {
          const blob = new Blob([toStixBundleData], { type: 'text/json' });
          const fileName = `${nowUTC()}_(export-stix-report)_${workspace.name}`;
          fileDownload(blob, fileName, 'application/json');
        }
      });
  };
  const handleExportDashboard = () => {
    handleExportJson(workspace);
  };
  const handleDashboardDuplication = () => {
    setDisplayDuplicate(true);
  };
  const [
    displayTurnToReportOrCaseContainer,
    setDisplayTurnToReportOrCaseContainer,
  ] = useState(false);
  const handleOpenTurnToReportOrCaseContainer = () => setDisplayTurnToReportOrCaseContainer(true);
  const handleCloseTurnToReportOrCaseContainer = () => setDisplayTurnToReportOrCaseContainer(false);
  const isGrantedToUpdateDashboard = useGranted([EXPLORE_EXUPDATE]);
  return (
    <>
      <div style={{ margin: variant === 'dashboard' ? '0 20px 0 20px' : 0 }}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
          style={{ marginRight: canEdit ? 0 : 10 }}
        >
          {workspace.name}
        </Typography>
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canEdit}>
          <div className={classes.popover}>
            <WorkspacePopover workspace={workspace} />
          </div>
        </Security>
        {variant === 'dashboard' && (
          <Security
            needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
            hasAccess={canEdit}
            placeholder={
              <div
                style={{
                  display: 'flex',
                  margin: '-5px 0 0 5px',
                  float: 'left',
                }}
              >
                <FormControl
                  variant="outlined"
                  size="small"
                  style={{ width: 194, marginRight: 20 }}
                >
                  <InputLabel id="relative" variant="outlined">
                    {t_i18n('Relative time')}
                  </InputLabel>
                  <Select
                    labelId="relative"
                    value={relativeDate ?? ''}
                    onChange={(value) => handleDateChange('relativeDate', value)}
                    disabled={true}
                    variant="outlined"
                    aria-label="date"
                  >
                    <MenuItem value="none">{t_i18n('None')}</MenuItem>
                    <MenuItem value="days-1">{t_i18n('Last 24 hours')}</MenuItem>
                    <MenuItem value="days-7">{t_i18n('Last 7 days')}</MenuItem>
                    <MenuItem value="months-1">{t_i18n('Last month')}</MenuItem>
                    <MenuItem value="months-3">{t_i18n('Last 3 months')}</MenuItem>
                    <MenuItem value="months-6">{t_i18n('Last 6 months')}</MenuItem>
                    <MenuItem value="years-1">{t_i18n('Last year')}</MenuItem>
                  </Select>
                </FormControl>
                <DatePicker
                  value={R.propOr(null, 'startDate', config)}
                  disableToolbar={true}
                  autoOk={true}
                  label={t_i18n('Start date')}
                  clearable={true}
                  disableFuture={true}
                  disabled={true}
                  aria-label="start picker"
                  onChange={(value, context) => !context.validationError && handleDateChange('startDate', value)}
                  slotProps={{
                    textField: {
                      style: { marginRight: 20 },
                      variant: 'outlined',
                      size: 'small',
                    },
                  }}
                />
                <DatePicker
                  value={R.propOr(null, 'endDate', config)}
                  disableToolbar={true}
                  autoOk={true}
                  label={t_i18n('End date')}
                  clearable={true}
                  disabled={true}
                  disableFuture={true}
                  aria-label="end picker"
                  onChange={(value, context) => !context.validationError && handleDateChange('endDate', value)}
                  slotProps={{
                    textField: {
                      style: { marginRight: 20 },
                      variant: 'outlined',
                      size: 'small',
                    },
                  }}
                />
              </div>
            }
          >
            <div
              style={{ display: 'flex', margin: '-5px 0 0 5px', float: 'left' }}
            >
              <FormControl
                size="small"
                style={{ width: 194, marginRight: 20 }}
                variant="outlined"
              >
                <InputLabel id="relative" variant="outlined">
                  {t_i18n('Relative time')}
                </InputLabel>
                <Select
                  labelId="relative"
                  value={relativeDate ?? ''}
                  onChange={(value) => handleDateChange('relativeDate', value)}
                  label={t_i18n('Relative time')}
                  variant="outlined"
                >
                  <MenuItem value="none">{t_i18n('None')}</MenuItem>
                  <MenuItem value="days-1">{t_i18n('Last 24 hours')}</MenuItem>
                  <MenuItem value="days-7">{t_i18n('Last 7 days')}</MenuItem>
                  <MenuItem value="months-1">{t_i18n('Last month')}</MenuItem>
                  <MenuItem value="months-3">{t_i18n('Last 3 months')}</MenuItem>
                  <MenuItem value="months-6">{t_i18n('Last 6 months')}</MenuItem>
                  <MenuItem value="years-1">{t_i18n('Last year')}</MenuItem>
                </Select>
              </FormControl>
              <DatePicker
                value={R.propOr(null, 'startDate', config)}
                disableToolbar={true}
                autoOk={true}
                label={t_i18n('Start date')}
                clearable={true}
                disableFuture={true}
                disabled={!!relativeDate}
                onChange={(value, context) => !context.validationError && handleDateChange('startDate', value)}
                slotProps={{
                  textField: {
                    style: { marginRight: 20 },
                    variant: 'outlined',
                    size: 'small',
                  },
                }}
              />
              <DatePicker
                value={R.propOr(null, 'endDate', config)}
                autoOk={true}
                label={t_i18n('End date')}
                clearable={true}
                disabled={!!relativeDate}
                disableFuture={true}
                onChange={(value, context) => !context.validationError && handleDateChange('endDate', value)}
                slotProps={{
                  textField: {
                    style: { marginRight: 20 },
                    variant: 'outlined',
                    size: 'small',
                  },
                }}
              />
            </div>
          </Security>
        )}
        {isFeatureEnable('PUBLIC_DASHBOARD') && variant === 'dashboard' && (
          <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
            <div style={{ margin: '-8px 0 0 4px', float: 'right' }}>
              <WorkspaceShareButton workspaceId={workspace.id} />
            </div>
          </Security>
        )}
        <WorkspaceDuplicationDialog
          workspace={workspace}
          displayDuplicate={displayDuplicate}
          handleCloseDuplicate={handleCloseDuplicate}
          duplicating={duplicating}
          setDuplicating={setDuplicating}
        />
        <div className={classes.export}>
          <ExportButtons
            domElementId="container"
            name={workspace.name}
            type={workspace.type}
            adjust={adjust}
            handleDownloadAsStixReport={handleDownloadAsStixReport}
            handleExportDashboard={handleExportDashboard}
            handleDashboardDuplication={isGrantedToUpdateDashboard && handleDashboardDuplication}
            variant={variant}
          />
          {widgetActions}
        </div>
        {variant === 'investigation' && (
          <Security needs={[INVESTIGATION_INUPDATE]}>
            <div className={classes.turnToReportOrCase}>
              <Tooltip title={t_i18n('Add to a container')}>
                <ToggleButtonGroup size="small" color="primary" exclusive={true}>
                  <ToggleButton
                    aria-label="Label"
                    onClick={handleOpenTurnToReportOrCaseContainer}
                    size="small"
                    value="add-to-a-container"
                  >
                    <MoveToInboxOutlined color="primary" fontSize="small" />
                  </ToggleButton>
                </ToggleButtonGroup>
              </Tooltip>
            </div>
          </Security>
        )}
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canManage}>
          <div className={classes.manageAccess}>
            <Tooltip title={t_i18n('Manage access restriction')}>
              <ToggleButtonGroup size="small" color="warning" exclusive={true}>
                <ToggleButton
                  aria-label={t_i18n('Manage access restriction')}
                  onClick={handleOpenManageAccess}
                  size="small"
                  value="manage-access"
                >
                  <LockPersonOutlined fontSize="small" color="primary" />
                </ToggleButton>
              </ToggleButtonGroup>
            </Tooltip>
            <WorkspaceManageAccessDialog
              workspaceId={workspace.id}
              open={displayManageAccess}
              authorizedMembersData={workspace}
              owner={workspace.owner}
              handleClose={handleCloseManageAccess}
            />
          </div>
        </Security>
        <div className={classes.tags}>
          {R.take(2, tags).map(
            (tag) => tag.length > 0 && (
            <Chip
              key={tag}
              classes={{ root: classes.tag }}
              label={tag}
              onDelete={() => deleteTag(tag)}
            />
            ),
          )}
          <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canEdit}>
            {tags.length > 1 ? (
              <IconButton
                color="primary"
                aria-label="More"
                onClick={handleToggleOpenTags}
                size="large"
                style={{ fontSize: 14, marginRight: '7px', marginTop: '-4px' }}
              >
                <DotsHorizontalCircleOutline fontSize="small" />
              </IconButton>
            ) : (
              <Tooltip title={t_i18n('Add tag')}>
                <IconButton
                  style={{ float: 'left', marginTop: '-5px', marginRight: '3px' }}
                  color="primary"
                  aria-label="Add tag"
                  onClick={handleOpenTag}
                  size="large"
                >
                  {openTag ? (
                    <CloseOutlined fontSize="small" />
                  ) : (
                    <AddOutlined fontSize="small" />
                  )}
                </IconButton>
              </Tooltip>
            )}
            <Slide
              direction="left"
              in={openTag}
              mountOnEnter={true}
              unmountOnExit={true}
            >
              <div style={{ float: 'left', marginTop: -5 }}>
                <Formik
                  initialValues={{ new_tag: '' }}
                  onSubmit={onSubmitCreateTag}
                >
                  <Form style={{ float: 'right' }}>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="new_tag"
                      aria-label="tag field"
                      autoFocus={true}
                      placeholder={t_i18n('New tag')}
                      onChange={handleChangeNewTags}
                      value={newTag}
                      className={classes.tagsInput}
                    />
                  </Form>
                </Formik>
              </div>
            </Slide>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={openTags}
              TransitionComponent={Transition}
              onClose={handleToggleOpenTags}
              fullWidth={true}
            >
              <DialogTitle>
                {t_i18n('Entity tags')}
                <Formik
                  initialValues={{ new_tag: '' }}
                  onSubmit={onSubmitCreateTag}
                >
                  {({ submitForm }) => (
                    <Form style={{ float: 'right' }}>
                      <Field
                        component={TextField}
                        variant="standard"
                        name="new_tag"
                        autoFocus={true}
                        placeholder={t_i18n('New tag')}
                        className={classes.tagsInput}
                        onChange={handleChangeNewTags}
                        value={newTag}
                        onKeyDown={(e) => {
                          if (e.keyCode === 13) {
                            return submitForm();
                          }
                          return true;
                        }}
                      />
                    </Form>
                  )}
                </Formik>
              </DialogTitle>
              <DialogContent dividers={true}>
                <List>
                  {tags.map(
                    (label) => label.length > 0 && (
                    <ListItem
                      key={label}
                      disableGutters={true}
                      dense={true}
                    >
                      <ListItemText primary={label} />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          aria-label="delete"
                          onClick={() => deleteTag(label)}
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
                    display: openTagsCreate ? 'block' : 'none',
                  }}
                >
                  <Formik
                    initialValues={{ new_tag: '' }}
                    onSubmit={onSubmitCreateTag}
                  >
                    {({ submitForm }) => (
                      <Form>
                        <Field
                          component={TextField}
                          variant="standard"
                          name="new_tag"
                          autoFocus={true}
                          fullWidth={true}
                          placeholder={t_i18n('New tags')}
                          className={classes.tagsInput}
                          onChange={handleChangeNewTags}
                          value={newTag}
                          onKeyDown={(e) => {
                            if (e.keyCode === 13) {
                              return submitForm();
                            }
                            return true;
                          }}
                        />
                      </Form>
                    )}
                  </Formik>
                </div>
              </DialogContent>
              <DialogActions>
                <Button onClick={handleToggleOpenTags} color="primary">
                  {t_i18n('Close')}
                </Button>
              </DialogActions>
            </Dialog>
          </Security>
        </div>
        {variant === 'investigation' && (
          <WorkspaceTurnToContainerDialog
            workspace={workspace}
            open={displayTurnToReportOrCaseContainer}
            handleClose={handleCloseTurnToReportOrCaseContainer}
          />
        )}
        <div className="clearfix" />
      </div>
    </>
  );
};

WorkspaceHeader.propTypes = {
  workspace: PropTypes.object,
  config: PropTypes.object,
  adjust: PropTypes.func,
  handleDateChange: PropTypes.func,
  variant: PropTypes.string,
};
export default WorkspaceHeader;
