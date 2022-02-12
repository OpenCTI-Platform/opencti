import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkersStatus, { workersStatusQuery } from './connectors/WorkersStatus';
import ConnectorsStatus, {
  connectorsStatusQuery,
} from './connectors/ConnectorsStatus';
import Loader from '../../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class Connectors extends Component {
  render() {
    const { classes } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={workersStatusQuery}
          render={({ props }) => {
            if (props) {
              return <WorkersStatus data={props} />;
            }
            return <div> &nbsp; </div>;
          }}
        />
        <QueryRenderer
          query={connectorsStatusQuery}
          render={({ props }) => {
            if (props) {
              return <ConnectorsStatus data={props} />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

Connectors.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  connectorsStatus: PropTypes.array,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(Connectors);
