import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import StixDomainEntityKnowledgeGraph, { stixDomainEntityKnowledgeGraphQuery } from './StixDomainEntityKnowledgeGraph';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class StixDomainEntityKnowledge extends Component {
  render() {
    const { classes, stixDomainEntityId } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={stixDomainEntityKnowledgeGraphQuery}
          variables={{
            id: stixDomainEntityId,
            count: 50,
          }}
          render={({ props }) => {
            if (props && props.stixDomainEntity && props.stixRelations) {
              return (
                <StixDomainEntityKnowledgeGraph
                  stixDomainEntity={props.stixDomainEntity}
                  stixRelations={props.stixRelations}
                />
              );
            }
            return (
              <div> &nbsp; </div>
            );
          }}
        />
      </div>
    );
  }
}

StixDomainEntityKnowledge.propTypes = {
  stixDomainEntityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKnowledge);
