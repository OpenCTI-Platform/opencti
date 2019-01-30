import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, find, insert, propEq,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { SubscriptionAvatars } from '../../../components/Subscription';
import ReportHeader from './ReportHeader';
import ReportKnowledgeGraph, { reportKnowledgeGraphQuery } from './ReportKnowledgeGraph';

const styles = theme => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 75,
  },
});

class ReportKnowledgeComponent extends Component {
  render() {
    const { classes, report, me } = this.props;
    const { editContext } = report;
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe ? insert(0, { name: me.email }, editContext) : editContext;
    return (
      <div className={classes.container}>
        <Drawer anchor='bottom' variant='permanent' classes={{ paper: classes.bottomNav }}>
          <div> &nbsp; </div>
        </Drawer>
        <ReportHeader report={report} variant='noMarking'/>
        <SubscriptionAvatars users={editUsers} variant='inGraph'/>
        <QueryRenderer
          query={reportKnowledgeGraphQuery}
          variables={{ id: report.id }}
          render={({ props }) => {
            if (props && props.report) {
              return <ReportKnowledgeGraph report={props.report}/>;
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

ReportKnowledgeComponent.propTypes = {
  report: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ReportKnowledge = createFragmentContainer(ReportKnowledgeComponent, {
  report: graphql`
      fragment ReportKnowledge_report on Report {
          id
          editContext {
              name
              focusOn
          }
          ...ReportHeader_report
      }
  `,
  me: graphql`
      fragment ReportKnowledge_me on User {
          email
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ReportKnowledge);
