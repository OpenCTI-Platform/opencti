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
import Select, { SelectChangeEvent } from '@mui/material/Select';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Slide from '@mui/material/Slide';
import { CloseOutlined, Delete, LabelOutlined, LockPersonOutlined, MoveToInboxOutlined } from '@mui/icons-material';
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
import { Dashboard_workspace$data } from '@components/workspaces/dashboards/__generated__/Dashboard_workspace.graphql';
import WorkspaceShareButton from 'src/private/components/workspaces/WorkspaceShareButton';
import WorkspaceDuplicationDialog from 'src/private/components/workspaces/WorkspaceDuplicationDialog';
import handleExportJson from 'src/private/components/workspaces/workspaceExportHandler';
import WorkspaceTurnToContainerDialog from 'src/private/components/workspaces/WorkspaceTurnToContainerDialog';
import { commitMutation, fetchQuery, MESSAGING$ } from 'src/relay/environment';
import Security from 'src/utils/Security';
import { nowUTC, parse } from 'src/utils/Time';
import useGranted, { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE } from 'src/utils/hooks/useGranted';
import WorkspacePopover from 'src/private/components/workspaces/WorkspacePopover';
import ExportButtons from 'src/components/ExportButtons';
import { useFormatter } from 'src/components/i18n';
import WorkspaceManageAccessDialog from 'src/private/components/workspaces/WorkspaceManageAccessDialog';
import Transition from 'src/components/Transition';
import { useGetCurrentUserAccessRight } from 'src/utils/authorizedMembers';
import { truncate } from 'src/utils/String';
import useHelper from 'src/utils/hooks/useHelper';
import WorkspaceWidgetConfig from 'src/private/components/workspaces/dashboards/WorkspaceWidgetConfig';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-10px',
  },
  manageAccess: {
    margin: '-5px 4px 0 0',
    float: 'right',
  },
  turnToReportOrCase: {
    margin: '-5px 4px 0 0',
    float: 'right',
  },
  export: {
    float: 'right',
    margin: '-5px 0 0 0',
    display: 'flex',
  },
  tags: {
    float: 'right',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'end',
    marginTop: '-5px',
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

type WorkspaceHeaderProps = {
  workspace: Dashboard_workspace$data;
  variant: 'dashboard' | 'investigation';
  adjust: () => void;
  handleDateChange: (type: string, value: string) => void;
};

const WorkspaceHeader = ({
  workspace,
  config,
  variant,
  adjust,
  handleDateChange,
  widgetActions,
  handleAddWidget,
}: WorkspaceHeaderProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [openTag, setOpenTag] = useState<boolean>(false);
  const [newTag, setNewTag] = useState<string>('');
  const [openTags, setOpenTags] = useState<boolean>(false);
  const [displayDuplicate, setDisplayDuplicate] = useState<boolean>(false);
  const [duplicating, setDuplicating] = useState<boolean>(false);
  const [displayManageAccess, setDisplayManageAccess] = useState<boolean>(false);

  const { canManage, canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);
  const tags: string[] = workspace.tags ?? [];

  const handleCloseDuplicate = () => setDisplayDuplicate(false);

  const handleOpenTag = () => {
    setOpenTag(!openTag);
  };

  const handleToggleOpenTags = () => {
    setOpenTags(!openTags);
  };

  const handleChangeRelativeDate = (event: SelectChangeEvent) => {
    const { value } = event.target;
    handleDateChange('relativeDate', value);
  };

  const handleChangeDate = (type: 'startDate' | 'endDate', value: Date) => {
    const formattedDate = value ? parse(value).format() : null;
    handleDateChange(type, formattedDate);
  };
  const handleChangeNewTags = (event: SelectChangeEvent) => setNewTag(event.target.value);

  const onSubmitCreateTag = (data, { resetForm, setSubmitting }) => {
    if (!tags.includes(newTag) && newTag !== '') {
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
        onError: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        updater: undefined,
      });
    }
    setOpenTag(false);
    setNewTag('');
    resetForm();
  };
  const deleteTag = (tagToDelete: string) => {
    const filteredTags = tags.filter((tag) => tag !== tagToDelete);

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
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      setSubmitting: undefined,
      updater: undefined,
    });
  };

  const handleOpenManageAccess = () => setDisplayManageAccess(true);
  const handleCloseManageAccess = () => setDisplayManageAccess(false);
  const handleDownloadAsStixReport = () => {
    fetchQuery(workspaceHeaderToStixReportBundleQuery, { id: workspace.id })
      .toPromise()
      .then((data) => {
        const toStixBundleData = data?.workspace?.toStixReportBundle;
        if (toStixBundleData) {
          const blob = new Blob([toStixBundleData], { type: 'text/json' });
          const fileName = `${nowUTC()}_(export-stix-report)_${workspace.name}.json`;
          fileDownload(blob, fileName);
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
        <Tooltip title={workspace.name}>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
            style={{ marginRight: canEdit ? 0 : 10 }}
          >
            {truncate(workspace.name, 40)}
          </Typography>
        </Tooltip>
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canEdit}>
          <div className={classes.popover}>
            <WorkspacePopover workspace={workspace} />
          </div>
        </Security>
        {variant === 'dashboard' && !isFABReplaced && (
          <Security
            needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
            hasAccess={canEdit}
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
                  value={config?.relativeDate ?? ''}
                  onChange={handleChangeRelativeDate}
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
                disabled={!!config?.relativeDate}
                onChange={(value: Date, context) => !context.validationError && handleChangeDate('startDate', value)}
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
                disabled={!!config?.relativeDate}
                disableFuture={true}
                onChange={(value: Date, context) => !context.validationError && handleChangeDate('endDate', value)}
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
        {variant === 'dashboard' && isFABReplaced && (
          <Security
            needs={[EXPLORE_EXUPDATE]}
            hasAccess={canEdit}
          >
            <div style={{ marginTop: '-6px', float: 'right' }}>
              <WorkspaceWidgetConfig onComplete={handleAddWidget} workspace={workspace}></WorkspaceWidgetConfig>
            </div>
          </Security>
        )}
        {variant === 'dashboard' && (
          <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
            <div style={{ margin: '-5px 0 0 0px', float: 'right' }}>
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
                <ToggleButtonGroup size="small" color="primary" exclusive>
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
              <ToggleButtonGroup size="small" color="warning" exclusive>
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
              <Tooltip title={openTag ? t_i18n('Cancel') : t_i18n('Add tag')}>
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
                    <LabelOutlined fontSize="small" />
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
              fullWidth
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
              <DialogContent dividers>
                <List>
                  {tags.map(
                    (label) => label.length > 0 && (
                    <ListItem
                      key={label}
                      disableGutters
                      dense
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
