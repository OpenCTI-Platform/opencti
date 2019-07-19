import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles/index';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import ConnectorsStatusContent, {
  connectorsStatusContentQuery,
} from './ConnectorsStatusContent';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ConnectorsStatus extends Component {
  render() {
    const { classes } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={connectorsStatusContentQuery}
          variables={{ prefix: 'import-connectors' }}
          render={({ props }) => {
            if (props) {
              return <ConnectorsStatusContent data={props} />;
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

ConnectorsStatus.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  connectorsStatus: PropTypes.array,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ConnectorsStatus);
