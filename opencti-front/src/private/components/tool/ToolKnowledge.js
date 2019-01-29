import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelations from '../stix_relation/EntityStixRelations';
import StixDomainEntityKnowledge from '../stix_domain_entity/StixDomainEntityKnowledge';
import StixRelation from '../stix_relation/StixRelation';
import ToolHeader from './ToolHeader';
import ToolKnowledgeBar from './ToolKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRelations = [
  'intrusion-set',
  'campaign',
  'incident',
];

class ToolKnowledgeComponent extends Component {
  render() {
    const { classes, tool, location } = this.props;
    const link = `/dashboard/knowledge/tools/${tool.id}/knowledge`;
    return (
      <div className={classes.container}>
        <ToolHeader tool={tool} variant='noalias'/>
        <ToolKnowledgeBar toolId={tool.id}/>
        <div className={classes.content}>
          <Route exact path='/dashboard/catalogs/tools/:toolId/knowledge/relations/:relationId' render={
            routeProps => <StixRelation entityId={tool.id} {...routeProps} inversedRelations={inversedRelations}/>
          }/>
          {location.pathname.includes('overview') ? <StixDomainEntityKnowledge stixDomainEntityId={tool.id}/> : ''}
          {location.pathname.includes('intrusion_sets') ? <EntityStixRelations entityId={tool.id} relationType='uses' targetEntityTypes={['Intrusion-Set']} entityLink={link}/> : ''}
          {location.pathname.includes('campaigns') ? <EntityStixRelations entityId={tool.id} relationType='uses' targetEntityTypes={['Campaign']} entityLink={link}/> : ''}
          {location.pathname.includes('incidents') ? <EntityStixRelations entityId={tool.id} relationType='uses' targetEntityTypes={['Incident']} entityLink={link}/> : ''}
        </div>
      </div>
    );
  }
}

ToolKnowledgeComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

const ToolKnowledge = createFragmentContainer(ToolKnowledgeComponent, {
  tool: graphql`
      fragment ToolKnowledge_tool on Tool {
          id
          ...ToolHeader_tool
      }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ToolKnowledge);
