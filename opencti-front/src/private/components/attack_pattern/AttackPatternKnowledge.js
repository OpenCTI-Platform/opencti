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
import AttackPatternHeader from './AttackPatternHeader';
import AttackPatternKnowledgeBar from './AttackPatternKnowledgeBar';

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
  'malware',
  'tool',
];

class AttackPatternKnowledgeComponent extends Component {
  render() {
    const { classes, attackPattern, location } = this.props;
    const link = `/dashboard/catalogs/attack_patterns/${
      attackPattern.id
    }/knowledge`;
    return (
      <div className={classes.container}>
        <AttackPatternHeader attackPattern={attackPattern} variant="noalias" />
        <AttackPatternKnowledgeBar attackPatternId={attackPattern.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/catalogs/attack_patterns/:attackPatternId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={attackPattern.id}
                inversedRelations={inversedRelations}
                {...routeProps}
              />
            )}
          />

          {location.pathname.includes('overview') ? (
            <StixDomainEntityKnowledge stixDomainEntityId={attackPattern.id} />
          ) : (
            ''
          )}

          {location.pathname.includes('intrusion_sets') ? (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Intrusion-Set']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('campaigns') ? (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Campaign']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('incidents') ? (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Incident']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('malwares') ? (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('tools') ? (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Tools']}
              entityLink={link}
            />
          ) : (
            ''
          )}
        </div>
      </div>
    );
  }
}

AttackPatternKnowledgeComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

const AttackPatternKnowledge = createFragmentContainer(
  AttackPatternKnowledgeComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternKnowledge_attackPattern on AttackPattern {
        id
        ...AttackPatternHeader_attackPattern
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatternKnowledge);
