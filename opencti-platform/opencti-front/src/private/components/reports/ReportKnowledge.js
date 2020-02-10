import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { DiagramEngine } from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import GlobalPortFactory from '../../../components/graph_node/GlobalPortFactory';
import EntityNodeFactory from '../../../components/graph_node/EntityNodeFactory';
import GlobalLinkFactory from '../../../components/graph_node/GlobalLinkFactory';
import GlobalLabelFactory from '../../../components/graph_node/GlobalLabelFactory';
import RelationNodeFactory from '../../../components/graph_node/RelationNodeFactory';
import { SubscriptionAvatars } from '../../../components/Subscription';
import ReportHeader from './ReportHeader';
import ReportKnowledgeGraph, { reportKnowledgeGraphQuery } from './ReportKnowledgeGraph';
import Loader from '../../../components/Loader';

const styles = (theme) => ({
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
  constructor(props) {
    super(props);
    const engine = new DiagramEngine();
    engine.installDefaultFactories();
    engine.registerPortFactory(new GlobalPortFactory());
    engine.registerLabelFactory(new GlobalLabelFactory());
    engine.registerLinkFactory(new GlobalLinkFactory());
    engine.registerNodeFactory(new EntityNodeFactory());
    engine.registerNodeFactory(new RelationNodeFactory());
    this.state = { engine };
  }

  render() {
    const { classes, report } = this.props;
    const { editContext } = report;
    return (
      <div className={classes.container}>
        <Drawer anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}>
          <div> &nbsp; </div>
        </Drawer>
        <ReportHeader report={report} variant="noMarking" />
        <SubscriptionAvatars context={editContext} variant="inGraph" />
        <QueryRenderer
          query={reportKnowledgeGraphQuery}
          variables={{ id: report.id }}
          render={({ props }) => {
            if (props && props.report) {
              return (
                <ReportKnowledgeGraph
                  report={props.report}
                  engine={this.state.engine}
                />
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

ReportKnowledgeComponent.propTypes = {
  report: PropTypes.object,
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
});

export default compose(inject18n, withStyles(styles))(ReportKnowledge);
