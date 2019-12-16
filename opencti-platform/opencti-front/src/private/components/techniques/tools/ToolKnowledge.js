import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityKnowledge from '../../common/stix_domain_entities/StixDomainEntityKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import ToolPopover from './ToolPopover';
import ToolKnowledgeBar from './ToolKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class ToolKnowledgeComponent extends Component {
  render() {
    const { classes, tool } = this.props;
    const link = `/dashboard/techniques/tools/${tool.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={tool}
          PopoverComponent={<ToolPopover />}
        />
        <ToolKnowledgeBar toolId={tool.id} />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={tool.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainEntityKnowledge
              stixDomainEntityId={tool.id}
              stixDomainEntityType="tool"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={tool.id}
              relationType="uses"
              targetEntityTypes={['Intrusion-Set']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={tool.id}
              relationType="uses"
              targetEntityTypes={['Campaign']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={tool.id}
              relationType="uses"
              targetEntityTypes={['Incident']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={tool.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

ToolKnowledgeComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ToolKnowledge = createFragmentContainer(ToolKnowledgeComponent, {
  tool: graphql`
    fragment ToolKnowledge_tool on Tool {
      id
      name
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ToolKnowledge);
