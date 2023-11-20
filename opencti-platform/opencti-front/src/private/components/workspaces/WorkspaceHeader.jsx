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
import {
  AddOutlined,
  CloseOutlined,
  MoveToInboxOutlined,
  LockPersonOutlined,
  ContentCopyOutlined,
} from '@mui/icons-material';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import PropTypes from 'prop-types';
import WorkspaceDuplicationDialog from './WorkspaceDuplicationDialog';
import handleExportJson from './workspaceExportHandler';
import WorkspaceTurnToContainerDialog from './WorkspaceTurnToContainerDialog';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { nowUTC } from '../../../utils/Time';
import { EXPLORE_EXUPDATE } from '../../../utils/hooks/useGranted';
import WorkspacePopover from './WorkspacePopover';
import ExportButtons from '../../../components/ExportButtons';
import { useFormatter } from '../../../components/i18n';
import WorkspaceManageAccessDialog from './WorkspaceManageAccessDialog';

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
  duplicate: {
    float: 'right',
    margin: '-8px 4px 0 0',
  },
  export: {
    float: 'right',
    margin: '-8px 0 0 0',
    display: 'flex',
  },
  tags: {
    float: 'right',
    marginTop: '-8px',
  },
  tag: {
    marginRight: 7,
    paddingBottom: 2,
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
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [openTag, setOpenTag] = useState(false);
  const [newTag, setNewTag] = useState('');
  const userCanManage = workspace.currentUserAccessRight === 'admin';
  const userCanEdit = userCanManage || workspace.currentUserAccessRight === 'edit';
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleCloseDuplicate = () => setDisplayDuplicate(false);
  const [duplicating, setDuplicating] = useState(false);
  const [moreButtonClicked, setMoreButtonClicked] = useState(false);
  const tags = R.propOr([], 'tags', workspace);

  const handleOpenTag = () => {
    setOpenTag(!openTag);
    if (tags.length > 0) {
      setMoreButtonClicked(true);
    }
  };
  const getCurrentTags = () => workspace.tags;
  const handleChangeNewTags = (event) => {
    const { value } = event.target;
    setNewTag(value);
  };
  const onSubmitCreateTag = (data, { resetForm, setSubmitting }) => {
    const currentTags = getCurrentTags();
    if (
      (currentTags === null || !currentTags.includes(newTag))
        && newTag !== ''
    ) {
      commitMutation({
        mutation: workspaceMutation,
        variables: {
          id: workspace.id,
          input: {
            key: 'tags',
            value: R.append(newTag, currentTags),
          },
        },
        setSubmitting,
        onCompleted: () => MESSAGING$.notifySuccess(t('The tag has been added')),
      });
    }
    setOpenTag(false);
    setNewTag('');
    setMoreButtonClicked(false);
    resetForm();
  };
  const deleteTag = (tag) => {
    const currentTags = getCurrentTags();
    const filteredTags = currentTags.filter((a) => a !== tag);
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        id: workspace.id,
        input: {
          key: 'tags',
          value: filteredTags,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(t('The tag has been removed')),
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

  return (
      <>
        <div style={{ margin: variant === 'dashboard' ? '0 20px 0 20px' : 0 }}>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
            style={{ marginRight: userCanEdit ? 0 : 10 }}
          >
            {workspace.name}
          </Typography>
          <Security needs={[EXPLORE_EXUPDATE]} hasAccess={userCanEdit}>
            <div className={classes.popover}>
              <WorkspacePopover workspace={workspace} />
            </div>
          </Security>
          {variant === 'dashboard' && (
            <Security
              needs={[EXPLORE_EXUPDATE]}
              hasAccess={userCanEdit}
              placeholder={
                <div style={{ display: 'flex', margin: '-5px 0 0 5px', float: 'left' }}>
                  <FormControl
                    variant="outlined"
                    size="small"
                    style={{ width: 194, marginRight: 20 }}
                  >
                    <InputLabel id="relative" variant="outlined">
                      {t('Relative time')}
                    </InputLabel>
                    <Select
                      labelId="relative"
                      value={relativeDate ?? ''}
                      onChange={(value) => handleDateChange('relativeDate', value)}
                      disabled={true}
                      variant="outlined"
                    >
                      <MenuItem value="none">{t('None')}</MenuItem>
                      <MenuItem value="days-1">{t('Last 24 hours')}</MenuItem>
                      <MenuItem value="days-7">{t('Last 7 days')}</MenuItem>
                      <MenuItem value="months-1">{t('Last month')}</MenuItem>
                      <MenuItem value="months-3">{t('Last 3 months')}</MenuItem>
                      <MenuItem value="months-6">{t('Last 6 months')}</MenuItem>
                      <MenuItem value="years-1">{t('Last year')}</MenuItem>
                    </Select>
                  </FormControl>
                  <DatePicker
                    value={R.propOr(null, 'startDate', config)}
                    disableToolbar={true}
                    autoOk={true}
                    label={t('Start date')}
                    clearable={true}
                    disableFuture={true}
                    disabled={true}
                    onChange={(value) => handleDateChange('startDate', value)}
                    renderInput={(params) => (
                      <TextField
                        style={{ marginRight: 20 }}
                        variant="outlined"
                        size="small"
                        {...params}
                      />
                    )}
                  />
                  <DatePicker
                    value={R.propOr(null, 'endDate', config)}
                    disableToolbar={true}
                    autoOk={true}
                    label={t('End date')}
                    clearable={true}
                    disabled={true}
                    disableFuture={true}
                    onChange={(value) => handleDateChange('endDate', value)}
                    renderInput={(params) => (
                      <TextField
                        style={{ marginRight: 20 }}
                        variant="outlined"
                        size="small"
                        {...params}
                      />
                    )}
                  />
                </div>
              }
            >
              <div style={{ display: 'flex', margin: '-5px 0 0 5px', float: 'left' }}>
                <FormControl
                  size="small"
                  style={{ width: 194, marginRight: 20 }}
                  variant="outlined"
                >
                  <InputLabel id="relative" variant="outlined">
                    {t('Relative time')}
                  </InputLabel>
                  <Select
                    labelId="relative"
                    value={relativeDate ?? relativeDate}
                    onChange={(value) => handleDateChange('relativeDate', value)}
                    label={t('Relative time')}
                    variant="outlined"
                  >
                    <MenuItem value="none">{t('None')}</MenuItem>
                    <MenuItem value="days-1">{t('Last 24 hours')}</MenuItem>
                    <MenuItem value="days-7">{t('Last 7 days')}</MenuItem>
                    <MenuItem value="months-1">{t('Last month')}</MenuItem>
                    <MenuItem value="months-3">{t('Last 3 months')}</MenuItem>
                    <MenuItem value="months-6">{t('Last 6 months')}</MenuItem>
                    <MenuItem value="years-1">{t('Last year')}</MenuItem>
                  </Select>
                </FormControl>
                <DatePicker
                  value={R.propOr(null, 'startDate', config)}
                  disableToolbar={true}
                  autoOk={true}
                  label={t('Start date')}
                  clearable={true}
                  disableFuture={true}
                  disabled={!!relativeDate}
                  onChange={(value) => handleDateChange('startDate', value)}
                  renderInput={(params) => (
                    <TextField
                      style={{ marginRight: 20 }}
                      variant="outlined"
                      size="small"
                      {...params}
                    />
                  )}
                />
                <DatePicker
                  value={R.propOr(null, 'endDate', config)}
                  autoOk={true}
                  label={t('End date')}
                  clearable={true}
                  disabled={!!relativeDate}
                  disableFuture={true}
                  onChange={(value) => handleDateChange('endDate', value)}
                  renderInput={(params) => (
                    <TextField variant="outlined" size="small" {...params} />
                  )}
                />
              </div>
            </Security>
          )}
          <div className={classes.export}>
            <ExportButtons
              domElementId="container"
              name={workspace.name}
              type={workspace.type}
              adjust={adjust}
              handleDownloadAsStixReport={handleDownloadAsStixReport}
            handleExportDashboard={handleExportDashboard}/>
          </div>
          {variant === 'investigation' && (
              <div className={classes.turnToReportOrCase}>
                <Tooltip title={t('Add to a container')}>
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
          )}
          <Security needs={[EXPLORE_EXUPDATE]} hasAccess={userCanManage}>
            <div className={classes.manageAccess}>
              <Tooltip title={t('Manage access')}>
                <ToggleButtonGroup size="small" color="warning" exclusive={true}>
                  <ToggleButton
                    aria-label="Label"
                    onClick={handleOpenManageAccess}
                    size="small"
                    value="manage-access"
                  >
                    <LockPersonOutlined fontSize="small" color="warning" />
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
            <div style={{ marginTop: moreButtonClicked ? '8px' : '-8px', float: 'right' }}>
              {R.take(1, tags).map(
                (tag) => tag.length > 0 && (
                  <Chip
                    key={tag}
                    classes={{ root: classes.tag }}
                    label={tag}
                    onDelete={() => deleteTag(tag)}
                  />
                ),
              )}
              <Security needs={[EXPLORE_EXUPDATE]} hasAccess={userCanEdit}>
                {tags.length > 1 ? (
                  <Button
                    color="primary"
                    aria-tag="More"
                    onClick={handleOpenTag}
                    style={{ fontSize: 14, marginRight: '7px' }}
                  >
                    <DotsHorizontalCircleOutline />
                    &nbsp;&nbsp;{t('More')}
                  </Button>
                ) : (
                  <Tooltip title={t('Add tag')}>
                    <IconButton
                      style={{ float: 'left', marginTop: '-6px' }}
                      color={openTag ? 'primary' : 'secondary'}
                      aria-tag="Tag"
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
                      <Form style={{ float: 'right', marginTop: '8px' }}>
                        <Field
                          component={TextField}
                          variant="standard"
                          name="new_tag"
                          autoFocus={true}
                          placeholder={t('New tag')}
                          onChange={handleChangeNewTags}
                          value={newTag}
                          className={classes.tagsInput}
                        />
                      </Form>
                    </Formik>
                  </div>
                </Slide>
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
