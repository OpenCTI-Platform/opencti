import React, { useState } from 'react';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MUITextField from '@mui/material/TextField';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import Select from '@mui/material/Select';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Slide from '@mui/material/Slide';
import { Add, Close } from '@mui/icons-material';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Button from '@mui/material/Button';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import Security from '../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../utils/hooks/useGranted';
import WorkspacePopover from './WorkspacePopover';
import ExportButtons from '../../../components/ExportButtons';
import { useFormatter } from '../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  export: {
    float: 'right',
    margin: '-8px 0 0 10px',
  },
  tags: {
    float: 'right',
    marginTop: '-5px',
  },
  tag: {
    marginRight: 7,
  },
  tagsInput: {
    margin: '4px 15px 0 10px',
    float: 'right',
  },
  viewAsField: {
    marginTop: -5,
    float: 'left',
  },
  viewAsFieldTag: {
    margin: '5px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
}));

const workspaceMutation = graphql`
  mutation WorkspaceHeaderFieldMutation($id: ID!, $input: [EditInput]!) {
    workspaceEdit(id: $id) {
      fieldPatch(input: $input) {
        tags
      }
    }
  }
`;

const WorkspaceHeader = ({ workspace, config, variant, adjust, handleDateChange }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [openTag, setOpenTag] = useState(false);
  const [openTags, setOpenTags] = useState(false);

  const handleToggleOpenTags = () => setOpenTags(!openTags);
  const handleToggleCreateTag = () => setOpenTag(!openTag);
  const getCurrentTags = () => workspace.tags;
  const onSubmitCreateTag = (data, { resetForm }) => {
    const currentTags = getCurrentTags();
    if ((currentTags === null || !currentTags.includes(data.new_tag)) && data.new_tag !== '') {
      commitMutation({
        mutation: workspaceMutation,
        variables: {
          id: workspace.id,
          input: {
            key: 'tags',
            value: R.append(data.new_tag, currentTags),
          },
        },
        onCompleted: () => MESSAGING$.notifySuccess(t('The tag has been added')),
      });
    }
    setOpenTag(false);
    resetForm();
  };
  const deleteTag = (tag) => {
    const currentTags = getCurrentTags();
    const tags = R.filter((a) => a !== tag, currentTags);
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        id: workspace.id,
        input: {
          key: 'tags',
          value: tags,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(t('The tag has been removed')),
    });
  };

  const tags = R.propOr([], 'tags', workspace);
  const { relativeDate } = config ?? {};
  return (
      <div style={{ margin: variant === 'dashboard' ? '0 20px 0 20px' : 0 }}>
        <Typography variant="h1" gutterBottom={true} classes={{ root: classes.title }}>
          {workspace.name}
        </Typography>
        <Security needs={[EXPLORE_EXUPDATE]}>
          <div className={classes.popover}>
            <WorkspacePopover id={workspace.id} type={workspace.type} />
          </div>
        </Security>
        {variant === 'dashboard' && (
          <Security needs={[EXPLORE_EXUPDATE]}
            placeholder={
              <div style={{ display: 'flex', margin: '-3px 0 0 5px', float: 'left' }}>
                <FormControl variant="outlined" size="small" style={{ width: 194, marginRight: 20 }}>
                  <InputLabel id="relative">{t('Relative time')}</InputLabel>
                  <Select labelId="relative" value={relativeDate ?? ''}
                    onChange={(value) => handleDateChange('relativeDate', value)}
                    disabled={true}>
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
                    <MUITextField
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
                    <MUITextField
                      style={{ marginRight: 20 }}
                      variant="outlined"
                      size="small"
                      {...params}
                    />
                  )}
                />
              </div>
            }>
            <div style={{ display: 'flex', margin: '-3px 0 0 5px', float: 'left' }}>
              <FormControl size="small" style={{ width: 194, marginRight: 20 }}>
                <InputLabel id="relative">{t('Relative time')}</InputLabel>
                <Select labelId="relative"
                  value={relativeDate ?? relativeDate}
                  onChange={handleDateChange.bind(this, 'relativeDate')}
                  label={t('Relative time')}>
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
                onChange={handleDateChange.bind(this, 'startDate')}
                renderInput={(params) => (
                  <MUITextField
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
                onChange={handleDateChange.bind(this, 'endDate')}
                renderInput={(params) => (
                  <MUITextField variant="outlined" size="small" {...params} />
                )}
              />
            </div>
          </Security>
        )}
        <div className={classes.export}>
          <ExportButtons domElementId="container" name={workspace.name} adjust={adjust}/>
        </div>
        <div className={classes.tags}>
          {R.take(5, tags).map(
            (tag) => tag.length > 0 && (
                <Chip
                  key={tag}
                  classes={{ root: classes.tag }}
                  label={tag}
                  onDelete={() => deleteTag(tag)}
                />
            ),
          )}
          <Security needs={[EXPLORE_EXUPDATE]}>
            {tags.length > 5 ? (
              <Button
                color="primary"
                aria-tag="More"
                onClick={handleToggleOpenTags}
                style={{ fontSize: 14 }}
              >
                <DotsHorizontalCircleOutline />
                &nbsp;&nbsp;{t('More')}
              </Button>
            ) : (
              <IconButton
                style={{ float: 'left', marginTop: -5 }}
                color={openTag ? 'primary' : 'secondary'}
                aria-tag="Tag"
                onClick={handleToggleCreateTag}
                size="large"
              >
                {openTag ? (
                  <Close fontSize="small" />
                ) : (
                  <Add fontSize="small" />
                )}
              </IconButton>
            )}
          </Security>
          <Slide direction="left" in={openTag} mountOnEnter={true} unmountOnExit={true}>
            <div style={{ float: 'left', marginTop: -5 }}>
              <Formik initialValues={{ new_tag: '' }} onSubmit={onSubmitCreateTag}>
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_tag"
                    autoFocus={true}
                    placeholder={t('New tag')}
                    className={classes.tagsInput}
                  />
                </Form>
              </Formik>
            </div>
          </Slide>
        </div>
        <div className="clearfix" />
      </div>
  );
};

export default WorkspaceHeader;
