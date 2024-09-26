import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
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
import StixCoreObjectOpinions from '../../analyses/opinions/StixCoreObjectOpinions';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemPatternType from '../../../../components/ItemPatternType';
import StixCoreObjectLabelsView from '../stix_core_objects/StixCoreObjectLabelsView';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemCreators from '../../../../components/ItemCreators';
import ItemConfidence from '../../../../components/ItemConfidence';
import ItemAuthor from '../../../../components/ItemAuthor';
import inject18n from '../../../../components/i18n';
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
import { Formik } from 'formik';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAssignees, convertParticipants } from '../../../../utils/edition';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
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
});

class StixDomainObjectOverview extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openStixIds: false,
      openAddAssignee: false,
      openAddParticipant: false,
    };
  }

  handleToggleOpenStixIds() {
    this.setState({ openStixIds: !this.state.openStixIds });
  }

  handleToggleAddAssignee() {
    this.setState({ openAddAssignee: !this.state.openAddAssignee });
  }

  handleToggleAddParticipant() {
    this.setState({ openAddParticipant: !this.state.openAddParticipant });
  }

  onSubmitAssignees(values) {
    console.log(values);
    // TODO : Mutation
    this.handleToggleAddAssignee();
  }

  onSubmitParticipant(values) {
    console.log(values);
    // TODO : Mutation
    this.handleToggleAddParticipant();
  }

  deleteStixId(stixId) {
    const { stixDomainObject } = this.props;
    const otherStixIds = stixDomainObject.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixDomainObject.standard_id && n !== stixId,
      otherStixIds,
    );
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: this.props.stixDomainObject.id,
        input: {
          key: 'x_opencti_stix_ids',
          value: stixIds,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The STIX ID has been removed')),
    });
  }

  render() {
    const {
      t,
      fldt,
      classes,
      stixDomainObject,
      withoutMarking,
      withPattern,
      displayAssignees,
      displayParticipants,
      displayConfidence = true,
      displayReliability = true,
    } = this.props;
    const otherStixIds = stixDomainObject.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixDomainObject.standard_id,
      otherStixIds,
    );
    const isReliabilityOfSource = !stixDomainObject.x_opencti_reliability;
    const reliability = isReliabilityOfSource
      ? stixDomainObject.createdBy?.x_opencti_reliability
      : stixDomainObject.x_opencti_reliability;

    const initialValues = {
      objectAssignee: convertAssignees(stixDomainObject),
      objectParticipant: convertParticipants(stixDomainObject),
    };

    return (
      <>
        <Typography variant="h4">
          {t('Basic information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              {stixDomainObject.objectMarking && (
                <>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Marking')}
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
                  {t('Author')}
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
                        {t('Reliability')}
                        {isReliabilityOfSource && (
                          <span style={{ fontStyle: 'italic' }}>
                            {' '}
                            ({t('of author')})
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
                        {t('Confidence level')}
                      </Typography>
                      <ItemConfidence
                        confidence={stixDomainObject.confidence}
                        entityType={stixDomainObject.entity_type}
                      />
                    </Grid>
                  )}
                </Grid>
              )}
              <StixCoreObjectOpinions stixCoreObjectId={stixDomainObject.id} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: -40 }}
              >
                {t('Original creation date')}
              </Typography>
              {fldt(stixDomainObject.created)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {fldt(stixDomainObject.modified)}
            </Grid>
            <Grid item xs={6}>
              {withPattern && (
                <>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Pattern type')}
                  </Typography>
                  <ItemPatternType label={stixDomainObject.pattern_type} />
                </>
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: withPattern ? 20 : 0 }}
              >
                {t('Processing status')}
              </Typography>
              <ItemStatus
                status={stixDomainObject.status}
                disabled={!stixDomainObject.workflowEnabled}
              />
              {displayAssignees && (
                <div>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Assignees')}
                    <IconButton
                      color="primary"
                      aria-label={t('Add new assignees')}
                      title={t('Add new assignees')}
                      onClick={this.handleToggleAddAssignee.bind(this)}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </Typography>
                  <ItemAssignees assignees={stixDomainObject.objectAssignee ?? []} />
                </div>
              )}
              {displayParticipants && (
                <div>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Participants')}
                    <IconButton
                      color="primary"
                      aria-label={t('Add new participant')}
                      title={t('Add new participant')}
                      onClick={this.handleToggleAddParticipant.bind(this)}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </Typography>
                  <ItemParticipants participants={stixDomainObject.objectParticipant ?? []}/>
                </div>
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Revoked')}
              </Typography>
              <ItemBoolean
                status={stixDomainObject.revoked}
                label={stixDomainObject.revoked ? t('Yes') : t('No')}
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
                {t('Platform creation date')}
              </Typography>
              {fldt(stixDomainObject.created_at)}
              <div>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t('Creators')}
                </Typography>
                <ItemCreators creators={stixDomainObject.creators ?? []} />
              </div>
              <div style={{ marginTop: 20 }}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Standard STIX ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                  <Tooltip
                    title={t(
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
                      onClick={this.handleToggleOpenStixIds.bind(this)}
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
          open={this.state.openStixIds}
          TransitionComponent={Transition}
          onClose={this.handleToggleOpenStixIds.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Other STIX IDs')}</DialogTitle>
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
                      onClick={this.deleteStixId.bind(this, stixId)}
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
              onClick={this.handleToggleOpenStixIds.bind(this)}
              color="primary"
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
        <Formik
          initialValues={initialValues}
          onSubmit={this.onSubmitAssignees.bind(this)}
          onReset={this.handleToggleAddAssignee.bind(this)}
        >
          {({ submitForm }) => (
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={this.state.openAddAssignee}
              TransitionComponent={Transition}
              onClose={this.handleToggleAddAssignee.bind(this)}
              fullWidth={true}
            >
              <DialogTitle>{t('Add new Assignees')}</DialogTitle>
              <DialogContent>
                <ObjectAssigneeField
                  name="objectAssignee"
                  style={fieldSpacingContainerStyle}
                />
              </DialogContent>
              <DialogActions>
                <Button
                  onClick={this.handleToggleAddAssignee.bind(this)}
                >
                  {t('Close')}
                </Button>
                <Button
                  onClick={submitForm}
                  color="secondary"
                >
                  {t('Add')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </Formik>
        <Formik
          initialValues={initialValues}
          onSubmit={this.onSubmitParticipant.bind(this)}
          onReset={this.handleToggleAddParticipant.bind(this)}
        >
          {({ submitForm }) => (
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={this.state.openAddParticipant}
              TransitionComponent={Transition}
              onClose={this.handleToggleAddParticipant.bind(this)}
              fullWidth={true}
            >
              <DialogTitle>{t('Add new Participant')}</DialogTitle>
              <DialogContent>
                <ObjectParticipantField
                  name="objectParticipant"
                  style={fieldSpacingContainerStyle}
                />
              </DialogContent>
              <DialogActions>
                <Button
                  onClick={this.handleToggleAddParticipant.bind(this)}
                >
                  {t('Close')}
                </Button>
                <Button
                  onClick={submitForm}
                  color="secondary"
                >
                  {t('Add')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </Formik>
      </>
    );
  }
}

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

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectOverview);
