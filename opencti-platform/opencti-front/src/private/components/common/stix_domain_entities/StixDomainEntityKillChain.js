import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixDomainEntityKillChainLines, {
  stixDomainEntityKillChainLinesStixRelationsQuery,
} from './StixDomainEntityKillChainLines';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

class StixDomainEntityKillChain extends Component {
  render() {
    const { stixDomainEntityId, entityLink } = this.props;
    const paginationOptions = {
      fromId: stixDomainEntityId,
      toTypes: ['Attack-Pattern'],
      relationType: 'uses',
      inferred: false,
    };
    return (
      <div>
        <QueryRenderer
          query={stixDomainEntityKillChainLinesStixRelationsQuery}
          variables={{ first: 500, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <StixDomainEntityKillChainLines
                  data={props}
                  entityLink={entityLink}
                  paginationOptions={paginationOptions}
                  stixDomainEntityId={stixDomainEntityId}
                />
              );
            }
            return <Loader withRightPadding={true} />;
          }}
        />
      </div>
    );
  }
}

StixDomainEntityKillChain.propTypes = {
  stixDomainEntityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKillChain);
