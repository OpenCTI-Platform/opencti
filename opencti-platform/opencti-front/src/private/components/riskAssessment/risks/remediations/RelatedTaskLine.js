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

import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import PersonIcon from '@material-ui/icons/Person';
import FlagIcon from '@material-ui/icons/Flag';
import Grid from '@material-ui/core/Grid';
import CardContent from '@material-ui/core/CardContent';
import Tooltip from '@material-ui/core/Tooltip';
import Divider from '@material-ui/core/Divider';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../../components/i18n';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import RelatedTaskPopover from './RelatedTaskPopover';
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
      relatedTaskId,
    } = this.props;
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
            style={{ padding: 0 }}
          >
            <CardContent className={classes.cardContent}>
              <FlagIcon fontSize='large' color="disabled" />
              <Grid container={true} style={{ marginLeft: '10px' }}>
                <Grid item={true} xs={12}>
                  <Typography align="left" variant="h2" style={{ textTransform: 'capitalize' }}>
                    {data.name && t(data.name)}
                  </Typography>
                </Grid>
                {!this.state.value ? <>
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
                </>: <Divider />}
              </Grid>
            </CardContent>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6} style={{ marginBottom: '10px' }}>                
                <div>
                  <Typography align="left" color="textSecondary" variant="h3">{t('Name')}</Typography>
                    {data.name && t(data.name)}
                </div>                
              </Grid>
              <Grid item={true} xs={6} style={{ marginBottom: '10px' }}>                
                <div style={{ marginLeft: '10px' }}>
                  <Typography align="left" color="textSecondary" variant="h3">{t('ID')}</Typography>
                    {data.id && t(data.id)}
                </div>                
              </Grid>              
              <Grid  item={true} xs={6} style={{ marginBottom: '10px' }}>
                <div>
                  <Typography align="left" color="textSecondary" variant="h3">{t('Task Type')}</Typography>
                  <div className={classes.cardContent}>
                    <FlagIcon fontSize='large' color="disabled" />
                    {data.task_type && t(data.task_type)}
                  </div>
                </div>
              </Grid>
              <Grid  item={true} xs={6} style={{ marginBottom: '10px' }}>
                <div style={{ marginLeft: '10px' }}>
                  <Typography align="left" color="textSecondary" variant="h3">{t('Dependency')}</Typography>
                  {taskDependency?.name && t(taskDependency?.name)}
                </div>
              </Grid>
              <Grid item={true} xs={6} style={{ marginBottom: '10px' }}>
                <div >
                  <Typography align="left" color="textSecondary" variant="h3">{t('Start Date')}</Typography>
                  {data.timing?.start_date && fsd(data.timing?.start_date)}
                </div>
              </Grid>
              <Grid item={true} xs={6} style={{ marginBottom: '10px' }}>
                <div style={{ marginLeft: '10px' }}>
                  <Typography align="left" color="textSecondary" variant="h3">{t('End Date')}</Typography>
                  {data.timing?.end_date && fsd(data.timing?.end_date)}
                </div>
              </Grid>
              <Grid item={true} xs={6} style={{ marginBottom: '10px' }}>
                <div>
                  <Typography align="left" color="textSecondary" variant="h3">{t('Related Tasks')}</Typography>
                  {data.related_tasks && data.related_tasks.map((task) => <div style={{marginBottom: '10px'}}>
                    <div style={{ marginBottom: '10px' }}>{t(task.name)}</div>
                  <Divider/></div>)}                    
                </div>
              </Grid>                            
              <Grid item={true} xs={6} style={{ marginBottom: '10px' }}>
                <div style={{ marginLeft: '10px' }}>
                  <Typography align="left" color="textSecondary" variant="h3">{t('Responsible Parties')}</Typography>
                  <div>                    
                    {data.responsible_roles && data.responsible_roles.map((role) => 
                    <div style={{ display: 'flex' }}>
                      <PersonIcon style={{ marginRight: '10px'}}/>
                      {t(role?.name)}
                      <Divider/>
                    </div>)}             
                  </div>
                </div>
              </Grid>       
              <Grid item={true} xs={12} style={{ marginBottom: '10px' }}>
                <Typography
                  color="textSecondary"
                  variant="h3"
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
                        rehypePlugins={[rehypeRaw]}
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
