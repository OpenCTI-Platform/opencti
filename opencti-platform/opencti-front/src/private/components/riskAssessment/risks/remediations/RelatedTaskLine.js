/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pipe,
  map,
  mergeAll,
  path,
  pathOr,
} from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Typography from '@material-ui/core/Typography';
import PersonIcon from '@material-ui/icons/Person';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import FlagIcon from '@material-ui/icons/Flag';
import Skeleton from '@material-ui/lab/Skeleton';
import Grid from '@material-ui/core/Grid';
import CardContent from '@material-ui/core/CardContent';
import GroupIcon from '@material-ui/icons/Group';
import Tooltip from '@material-ui/core/Tooltip';
import MoreVertIcon from '@material-ui/icons/MoreVert';
import IconButton from '@material-ui/core/IconButton';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import Button from '@material-ui/core/Button';
import * as R from 'ramda';
import { AutoFix, Information } from 'mdi-material-ui';
import inject18n from '../../../../../components/i18n';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import ItemConfidence from '../../../../../components/ItemConfidence';
import RemediationPopover from './RemediationPopover';
import { resolveLink } from '../../../../../utils/Entity';
import ItemIcon from '../../../../../components/ItemIcon';
import RelatedTaskPopover from './RelatedTaskPopover';
import { defaultValue } from '../../../../../utils/Graph';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreobjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
  },
  ListItem: {
    display: 'grid',
    gridTemplateColumns: '20% 15% 15% 15% 1fr 1fr',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    float: 'left',
    height: '48px',
    display: 'flex',
    overflow: 'hidden',
    fontSize: '13px',
    alignItems: 'center',
    whiteSpace: 'nowrap',
    textOverflow: 'ellipsis',
    justifyContent: 'left',
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatarIcon: {
    width: '35px',
    height: '35px',
    color: 'white',
  },
  cardContent: {
    display: 'flex',
    alignItems: 'center',
  },
  accordionDetails: {
    display: 'block',
  },
  buttonExpand: {
    position: 'absolute',
    bottom: 2,
    width: '100%',
    height: 25,
    backgroundColor: 'rgba(255, 255, 255, .2)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor: 'rgba(255, 255, 255, .5)',
    },
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
});

class RelatedTaskLine extends Component {
  constructor(props) {
    super(props);
    this.state = {
      removing: false,
      expanded: false,
      value: false,
    };
  }

  handleClick() {
    this.setState({
      value: !this.state.value,
    });
  }

  handleOpenDialog(requiredResourcesEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: requiredResourcesEdge,
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeExternalReference: null,
    };
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeExternalReference(this.state.removeExternalReference);
  }

  render() {
    const {
      fsd,
      t,
      fldt,
      refreshQuery,
      classes,
      data,
      remediationId,
      displayRelation,
      entityId,
      relatedTaskId,
    } = this.props;
    const { expanded } = this.state;
    const taskDependency = pipe(
      pathOr([], ['task_dependencies']),
      mergeAll,
    )(data);
    const responsibleRoles = pipe(
      pathOr([], ['responsible_roles']),
      mergeAll,
      path(['parties']),
    )(data);
    return (
      <div style={{
        display: 'grid',
        gridTemplateColumns: '90% 10%',
        borderBottom: '1px solid grey',
        margin: '0 20px',
      }}>
        <Accordion style={{ borderBottom: '0', boxShadow: 'none' }}>
          <AccordionSummary
            onClick={() => this.handleClick()}
            expandIcon={<ExpandMoreIcon />}
            aria-controls="panel1a-content"
            id="panel1a-header"
          >
            {this.state.value ? '' : (
              <CardContent className={classes.cardContent}>
                <FlagIcon fontSize='large' color="disabled" />
                <Grid container={true} style={{ marginLeft: '10px' }}>
                  <Grid item={true} xs={12}>
                    <Typography align="left" variant="h2" style={{ textTransform: 'capitalize' }}>
                      {data.name && t(data.name)}
                    </Typography>
                  </Grid>
                  <Grid style={{ display: 'flex' }} item={true} xs={6}>
                    <Typography align="left" color="textSecondary" variant="h3">
                      {t('Start Date: ')}
                    </Typography>
                    <Typography align="left" color="textSecondary" variant="h3">
                      {data.timing?.start_date && fldt(data.timing?.start_date)}
                    </Typography>
                  </Grid>
                  <Grid style={{ display: 'flex' }} item={true} xs={6}>
                    <Typography align="left" color="textSecondary" variant="h3">
                      {t('End Date: ')}
                    </Typography>
                    <Typography align="left" color="textSecondary" variant="h3">
                      {data.timing?.end_date && fldt(data.timing?.end_date)}
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            )
            }
          </AccordionSummary>
          <AccordionDetails classes={{ root: classes.accordionDetails }}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <Grid style={{
                  display: 'flex',
                  alignItems: 'center',
                  marginBottom: '15px',
                  marginLeft: '1px',
                }}>
                  <div style={{ marginLeft: '10px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('Name')}</Typography>
                    <Typography align="left" variant="subtitle1">
                      {data.name && t(data.name)}
                    </Typography>
                  </div>
                </Grid>
              </Grid>
              <Grid item={true} xs={6}>
                <Grid style={{
                  display: 'flex',
                  alignItems: 'center',
                  marginBottom: '15px',
                  marginLeft: '-4px',
                }}>
                  <div style={{ marginLeft: '10px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('ID')}</Typography>
                    <Typography align="left" variant="subtitle1">
                      {data.id && t(data.id)}
                    </Typography>
                  </div>
                </Grid>
              </Grid>
            </Grid>
            <Grid container={true}>
              <Grid item={true} xs={6}>
                <Grid style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
                  <div style={{ marginLeft: '10px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('Task Type')}</Typography>
                    <div className={classes.cardContent}>
                      <FlagIcon fontSize='large' color="disabled" />
                      <Typography style={{ marginLeft: '10px' }} align="center" variant="subtitle1">
                        {data.task_type && t(data.task_type)}
                      </Typography>
                    </div>
                  </div>
                </Grid>
                <Grid item={true} xs={6} className={classes.cardContent} style={{ marginBottom: '15px' }}>
                  <div style={{ marginLeft: '10px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('Start Date')}</Typography>
                    <Typography align="left" variant="subtitle1">
                      {/* {t('21 June 2021')} */}
                      {data.timing?.start_date && fsd(data.timing?.start_date)}
                    </Typography>
                  </div>
                </Grid>
                <Grid item={true} xs={6} className={classes.cardContent} style={{ marginBottom: '15px' }}>
                  <div style={{ marginLeft: '10px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('Tasks')}</Typography>
                    <Typography align="left" variant="subtitle1">
                      {t('Hello world')}
                    </Typography>
                  </div>
                </Grid>
              </Grid>
              <Grid item={true} xs={6}>
                <Grid className={classes.cardContent} style={{ marginBottom: '20px' }}>
                  <div style={{ marginLeft: '18px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('Dependency')}</Typography>
                    <Typography align="left" variant="subtitle1">
                      {taskDependency?.name && t(taskDependency?.name)}
                    </Typography>
                  </div>
                </Grid>
                <Grid item={true} xs={6} style={{
                  display: 'flex',
                  alignItems: 'center',
                  marginBottom: '15px',
                }}>
                  <div style={{ marginLeft: '18px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('End Date')}</Typography>
                    <Typography align="left" variant="subtitle1">
                      {data.timing?.end_date && fsd(data.timing?.end_date)}
                    </Typography>
                  </div>
                </Grid>
                <Grid item={true} xs={6} style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
                  <div style={{ marginLeft: '18px' }}>
                    <Typography align="left" color="textSecondary" variant="h3">{t('Responsible Parties')}</Typography>
                    <div className={classes.cardContent}>
                      <PersonIcon className={classes.avatarIcon} />
                      <div style={{ marginLeft: '10px' }}>
                        <Typography variant="subtitle1">
                          {responsibleRoles?.name && t(responsibleRoles?.name)}
                        </Typography>
                        {responsibleRoles?.party_type && t(responsibleRoles?.party_type)}
                      </div>
                    </div>
                  </div>
                </Grid>
              </Grid>
            </Grid>
            <Grid container={true}>
              <Grid item={true} xs={12} style={{ marginBottom: '10px' }}>
                <Typography
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Description')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title='Description'
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      <Markdown
                        remarkPlugins={[remarkGfm, remarkParse]}
                        parserOptions={{ commonmark: true }}
                        className="markdown"
                      >
                        {data.description && t(data.description)}
                      </Markdown>
                    </div>
                  </div>
                </div>
              </Grid>
              <Grid style={{ marginTop: '20px' }} xs={12} item={true}>
                <CyioCoreobjectExternalReferences
                  refreshQuery={refreshQuery}
                  fieldName='links'
                  typename={data.__typename}
                  externalReferences={data.links}
                  cyioCoreObjectId={data.id}
                />
              </Grid>
              <Grid style={{ margin: '50px 0 20px 0' }} xs={12} item={true}>
                <CyioCoreObjectOrCyioCoreRelationshipNotes
                  refreshQuery={refreshQuery}
                  typename={data.__typename}
                  fieldName='remarks'
                  notes={data.remarks}
                  cyioCoreObjectOrCyioCoreRelationshipId={data.id}
                  marginTop='0px'
                />
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
        <div style={{ marginTop: '30px' }}>
          <RelatedTaskPopover
            refreshQuery={refreshQuery}
            handleRemove={this.handleOpenDialog.bind(this)}
            remediationId={remediationId}
            data={data}
            relatedTaskId={relatedTaskId}
          />
        </div>
      </div>
    );
  }
}

RelatedTaskLine.propTypes = {
  paginationOptions: PropTypes.object,
  remediationId: PropTypes.string,
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  data: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
  fsd: PropTypes.func,
  displayRelation: PropTypes.bool,
  entityId: PropTypes.string,
  relatedTaskId: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RelatedTaskLine);
