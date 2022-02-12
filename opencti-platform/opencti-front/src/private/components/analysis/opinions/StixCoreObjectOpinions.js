import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOpinionsRadar, {
  stixCoreObjectOpinionsRadarDistributionQuery,
} from './StixCoreObjectOpinionsRadar';

const styles = () => ({
  container: {
    marign: 0,
  },
});

class StixCoreObjectOpinions extends Component {
  render() {
    const { title, variant, height, marginTop, stixCoreObjectId, field } = this.props;
    const opinionsDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'opinion',
      operation: 'count',
      limit: 8,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectOpinionsRadarDistributionQuery}
        variables={opinionsDistributionVariables}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreObjectOpinionsRadar
                stixCoreObjectId={stixCoreObjectId}
                data={props}
                title={title}
                variant={variant}
                height={height}
                marginTop={marginTop}
                paginationOptions={opinionsDistributionVariables}
              />
            );
          }
          return <div />;
        }}
      />
    );
  }
}

StixCoreObjectOpinions.propTypes = {
  data: PropTypes.object,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  variant: PropTypes.string,
  height: PropTypes.number,
  marginTop: PropTypes.number,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectOpinions);
