import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { Add, BrushOutlined, Delete } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { Formik } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import ObjectAssigneeField from '../form/ObjectAssigneeField';
import ObjectParticipantField from '../form/ObjectParticipantField';
import StixCoreObjectOpinions from '../../analyses/opinions/StixCoreObjectOpinions';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemPatternType from '../../../../components/ItemPatternType';
import StixCoreObjectLabelsView from '../stix_core_objects/StixCoreObjectLabelsView';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemCreators from '../../../../components/ItemCreators';
import ItemConfidence from '../../../../components/ItemConfidence';
import ItemAuthor from '../../../../components/ItemAuthor';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { stixDomainObjectMutation } from './StixDomainObjectHeader';
import ItemStatus from '../../../../components/ItemStatus';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';
import ItemAssignees from '../../../../components/ItemAssignees';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ItemParticipants from '../../../../components/ItemParticipants';
import Transition from '../../../../components/Transition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  standard_id: {
    padding: '5px 5px 5px 10px',
    fontFamily: 'Consolas, monaco, monospace',
    fontSize: 11,
    backgroundColor:
      theme.palette.mode === 'light'
        ? 'rgba(0, 0, 0, 0.02)'
        : 'rgba(255, 255, 255, 0.02)',
    lineHeight: '18px',
  },
}));

const StixDomainObjectOverview = ({
  stixDomainObject,
  withoutMarking,
  withPattern = false,
  displayAssignees,
  displayParticipants,
  displayConfidence = true,
  displayReliability = true,
  displayOpinions = true,
}) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const [openStixIds, setOpenStixIds] = useState(false);
  const [openAddAssignee, setOpenAddAssignee] = useState(false);
  const [openAddParticipant, setOpenAddParticipant] = useState(false);

  const handleToggleOpenStixIds = () => {
    setOpenStixIds(!openStixIds);
  };

  const handleToggleAddAssignee = () => {
    setOpenAddAssignee(!openAddAssignee);
  };

  const handleToggleAddParticipant = () => {
    setOpenAddParticipant(!openAddParticipant);
  };

  const onSubmitAssignees = (values, { setSubmitting, resetForm }) => {
    const currentAssigneesIds = stixDomainObject.objectAssignee.map((assignee) => assignee.id);
    const valuesIds = values.objectAssignee.map((assignee) => assignee.value);
    const allIds = [...new Set([...currentAssigneesIds, ...valuesIds])]; // 'new Set' to merge without duplicates
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObject.id,
        input: {
          key: 'objectAssignee',
          value: allIds,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleToggleAddAssignee();
      },
    });
  };

  const onSubmitParticipant = (values, { setSubmitting, resetForm }) => {
    const currentParticipantsIds = stixDomainObject.objectParticipant.map((participant) => participant.id);
    const valuesIds = values.objectParticipant.map((participant) => participant.value);
    const allIds = [...new Set([...currentParticipantsIds, ...valuesIds])]; // 'new Set' to merge without duplicates
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObject.id,
        input: {
          key: 'objectParticipant',
          value: allIds,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleToggleAddParticipant();
      },
    });
  };

  const deleteStixId = (stixId) => {
    const otherStixIds = stixDomainObject.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixDomainObject.standard_id && n !== stixId,
      otherStixIds,
    );
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObject.id,
        input: {
          key: 'x_opencti_stix_ids',
          value: stixIds,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The STIX ID has been removed')),
    });
  };

  const otherStixIds = stixDomainObject.x_opencti_stix_ids || [];
  const stixIds = R.filter(
    (n) => n !== stixDomainObject.standard_id,
    otherStixIds,
  );
  const isReliabilityOfSource = !stixDomainObject.x_opencti_reliability;
  const reliability = isReliabilityOfSource
    ? stixDomainObject.createdBy?.x_opencti_reliability
    : stixDomainObject.x_opencti_reliability;

  return (
    <>
      <Typography variant="h4">
        {t_i18n('Basic information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            {stixDomainObject.objectMarking && (
              <>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Marking')}
                </Typography>
                <ItemMarkings
                  markingDefinitions={
                    stixDomainObject.objectMarking ?? []
                  }
                />
              </>
            )}
            <div>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{
                  marginTop:
                    withPattern
                    || (!withoutMarking && stixDomainObject.objectMarking)
                      ? 20
                      : 0,
                }}
              >
                {t_i18n('Author')}
              </Typography>
              <ItemAuthor
                createdBy={R.propOr(null, 'createdBy', stixDomainObject)}
              />
            </div>
            {(displayConfidence || displayReliability) && (
              <Grid container={true} columnSpacing={1}>
                {displayReliability && (
                  <Grid item xs={6}>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t_i18n('Reliability')}
                      {isReliabilityOfSource && (
                        <span style={{ fontStyle: 'italic' }}>
                          {' '}
                          ({t_i18n('of author')})
                        </span>
                      )}
                    </Typography>
                    <ItemOpenVocab
                      displayMode="chip"
                      type="reliability_ov"
                      value={reliability?.toString()}
                    />
                  </Grid>
                )}
                {displayConfidence && (
                  <Grid item xs={6}>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t_i18n('Confidence level')}
                    </Typography>
                    <ItemConfidence
                      confidence={stixDomainObject.confidence}
                      entityType={stixDomainObject.entity_type}
                    />
                  </Grid>
                )}
              </Grid>
            )}
            {displayOpinions && <StixCoreObjectOpinions stixCoreObjectId={stixDomainObject.id} />}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Original creation date')}
            </Typography>
            {fldt(stixDomainObject.created)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Modification date')}
            </Typography>
            {fldt(stixDomainObject.modified)}
          </Grid>
          <Grid item xs={6}>
            {withPattern && (
              <>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Pattern type')}
                </Typography>
                <ItemPatternType label={stixDomainObject.pattern_type} />
              </>
            )}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: withPattern ? 20 : 0 }}
            >
              {t_i18n('Processing status')}
            </Typography>
            <ItemStatus
              status={stixDomainObject.status}
              disabled={!stixDomainObject.workflowEnabled}
            />
            {displayAssignees && (
              <div data-testid='sdo-overview-assignees'>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t_i18n('Assignees')}
                  </Typography>
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <IconButton
                      color="primary"
                      aria-label={t_i18n('Add new assignees')}
                      title={t_i18n('Add new assignees')}
                      onClick={handleToggleAddAssignee}
                      style={{ margin: '0 0 -14px 0' }}
                      size="large"
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </Security>
                </div>
                <ItemAssignees assignees={stixDomainObject.objectAssignee ?? []} stixDomainObjectId={stixDomainObject.id} />
              </div>
            )}
            {displayParticipants && (
              <div data-testid='sdo-overview-participants'>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t_i18n('Participants')}
                  </Typography>
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <IconButton
                      color="primary"
                      aria-label={t_i18n('Add new participants')}
                      title={t_i18n('Add new participants')}
                      onClick={handleToggleAddParticipant}
                      style={{ margin: '0 0 -14px 0' }}
                      size="large"
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </Security>
                </div>
                <ItemParticipants participants={stixDomainObject.objectParticipant ?? []} stixDomainObjectId={stixDomainObject.id} />
              </div>
            )}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Revoked')}
            </Typography>
            <ItemBoolean
              status={stixDomainObject.revoked}
              label={stixDomainObject.revoked ? t_i18n('Yes') : t_i18n('No')}
              reverse={true}
            />
            <StixCoreObjectLabelsView
              labels={stixDomainObject.objectLabel}
              id={stixDomainObject.id}
              marginTop={20}
              entity_type={stixDomainObject.entity_type}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Platform creation date')}
            </Typography>
            {fldt(stixDomainObject.created_at)}
            <div>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t_i18n('Creators')}
              </Typography>
              <ItemCreators creators={stixDomainObject.creators ?? []} />
            </div>
            <div style={{ marginTop: 20 }}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t_i18n('Standard STIX ID')}
              </Typography>
              <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                <Tooltip
                  title={t_i18n(
                    'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                  )}
                >
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <div style={{ float: 'right', margin: '-5px 0 0 8px' }}>
                  <IconButton
                    aria-label="Close"
                    disableRipple={true}
                    size="small"
                    disabled={stixIds.length === 0}
                    onClick={handleToggleOpenStixIds}
                  >
                    <BrushOutlined
                      fontSize="small"
                      color={stixIds.length === 0 ? 'inherit' : 'primary'}
                    />
                  </IconButton>
                </div>
              </Security>
              <div className="clearfix" />
              <div className={classes.standard_id}>
                <ItemCopy content={stixDomainObject.standard_id} />
              </div>
            </div>
          </Grid>
        </Grid>
      </Paper>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openStixIds}
        TransitionComponent={Transition}
        onClose={handleToggleOpenStixIds}
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Other STIX IDs')}</DialogTitle>
        <DialogContent dividers={true}>
          <List>
            {stixIds.map(
              (stixId) => stixId.length > 0 && (
              <ListItem key={stixId} disableGutters={true} dense={true}>
                <ListItemText primary={stixId} />
                <ListItemSecondaryAction>
                  <IconButton
                    edge="end"
                    aria-label="delete"
                    onClick={() => deleteStixId(stixId)}
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
          <Button
            onClick={handleToggleOpenStixIds}
            color="primary"
          >
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
      <Formik
        initialValues={{}}
        onSubmit={onSubmitAssignees}
        onReset={handleToggleAddAssignee}
      >
        {({ submitForm, handleReset }) => (
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={openAddAssignee}
            TransitionComponent={Transition}
            onClose={handleToggleAddAssignee}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Add new assignees')}</DialogTitle>
            <DialogContent>
              <ObjectAssigneeField
                name="objectAssignee"
                style={fieldSpacingContainerStyle}
              />
            </DialogContent>
            <DialogActions>
              <Button
                onClick={handleReset}
              >
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={submitForm}
                color="secondary"
              >
                {t_i18n('Add')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
      <Formik
        initialValues={{}}
        onSubmit={onSubmitParticipant}
        onReset={handleToggleAddParticipant}
      >
        {({ submitForm }) => (
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={openAddParticipant}
            TransitionComponent={Transition}
            onClose={handleToggleAddParticipant}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Add new participants')}</DialogTitle>
            <DialogContent>
              <ObjectParticipantField
                name="objectParticipant"
                style={fieldSpacingContainerStyle}
              />
            </DialogContent>
            <DialogActions>
              <Button
                onClick={handleToggleAddParticipant}
              >
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={submitForm}
                color="secondary"
              >
                {t_i18n('Add')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

StixDomainObjectOverview.propTypes = {
  stixDomainObject: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  withoutMarking: PropTypes.bool,
  displayAssignees: PropTypes.bool,
  displayParticipants: PropTypes.bool,
  displayConfidence: PropTypes.bool,
  displayReliability: PropTypes.bool,
};

export default StixDomainObjectOverview;
