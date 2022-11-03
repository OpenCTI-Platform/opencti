import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { createFragmentContainer } from 'react-relay';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../../components/i18n';
import {
  RemediationEntityLine,
} from './RemediationEntityLine';
import RemediationCreation from './RemediationCreation';

const styles = () => ({
  paper: {
    listStyle: 'none',
    height: '100%',
    boxShadow: 'none',
    padding: '0 10px',
  },
  ListItem: {
    width: '97%',
    display: 'grid',
    gridTemplateColumns: '19.7% 15% 15.5% 15% 1fr 1fr',
  },
  bodyItem: {
    height: 35,
    float: 'left',
    whiteSpace: 'nowrap',
  },
});

class RemediationEntitiesLines extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openCreation: false,
    };
  }
  // componentDidMount() {
  //   this.subscription = interval$.subscribe(() => {
  //     this.props.relay.refetchConnection(25);
  //   });
  // }

  // componentWillUnmount() {
  //   this.subscription.unsubscribe();
  // }

  handleOpen() {
    this.setState({ openCreation: true });
  }

  handleClose() {
    this.setState({ openCreation: false });
  }

  handleOpenCreation() {
    this.setState({ openCreation: false });
  }

  render() {
    const {
      classes,
      history,
      t,
      risk,
      riskId,
      refreshQuery,
      entityId,
      location,
    } = this.props;
    const RemediationEntitiesLogEdges = R.pathOr([], ['remediations'], risk);

    return (
      <div>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Remediations')}
        </Typography>
        {/* <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        > */}
        <RemediationCreation
        location={location}
        remediationId={entityId}
        riskId={riskId}
        history={history}
        refreshQuery={refreshQuery}
        openCreation={this.state.openCreation}
        handleCreation={this.handleOpen.bind(this)}
        handleOpenCreation={this.handleOpenCreation.bind(this)}
      />
      <div className="clearfix" />
      <Paper className={classes.paper} elevation={2}>
        <ListItem style={{ borderBottom: '2px solid white' }}>
          <ListItemText
            primary={<div className={classes.ListItem} >
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Source')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Name')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Response Type')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Lifecycle')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Start Date')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('End Date')}
                </Typography>
              </div>
            </div>}
          />
        </ListItem>
        {(RemediationEntitiesLogEdges.length > 0 ? (RemediationEntitiesLogEdges.map(
          (remediationEdge) => <RemediationEntityLine
            node={remediationEdge}
            riskData={risk}
            key={remediationEdge.id}
            history={history}
            riskId={riskId}
            remediationId={entityId}
            refreshQuery={refreshQuery}
            location={location}
          />,
        )) : <div style={{ textAlign: 'center', padding: '20px 0' }}>
          No Record Found </div>)}
      </Paper>
      </div>
    );
  }
}

RemediationEntitiesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  riskId: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
  risk: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  displayRelation: PropTypes.bool,
  location: PropTypes.object,
};

const RemediationEntitiesLinesFragment = createFragmentContainer(
  RemediationEntitiesLines,
  {
    risk: graphql`
    fragment RemediationEntitiesLines_risk on Risk{
      id
      created
      modified
      remediations {
        ...RemediationEntityLine_node
      }
    }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RemediationEntitiesLinesFragment);
