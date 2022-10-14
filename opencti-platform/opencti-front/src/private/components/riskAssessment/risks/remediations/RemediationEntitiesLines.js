import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { createFragmentContainer } from 'react-relay';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import { IconButton } from '@material-ui/core';
import { Add } from '@material-ui/icons';
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

  render() {
    const {
      classes,
      history,
      t,
      risk,
      riskId,
      refreshQuery,
      entityId,
    } = this.props;
    const RemediationEntitiesLogEdges = R.pathOr([], ['remediations'], risk);

    return (
      <div>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Remediations new')}
        </Typography>
        {/* <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        > */}
        <RemediationCreation
        remediationId={entityId}
        riskId={riskId}
        history={history}
        refreshQuery={refreshQuery}
      />
      <Paper className={classes.paper}>
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
