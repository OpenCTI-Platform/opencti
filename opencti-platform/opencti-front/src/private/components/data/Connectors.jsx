import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import BreadcrumbHeader from '../../../components/BreadcrumbHeader';
import IngestionMenu from './IngestionMenu';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkersStatus, { workersStatusQuery } from './connectors/WorkersStatus';
import ConnectorsStatus, { connectorsStatusQuery } from './connectors/ConnectorsStatus';
import Loader from '../../../components/Loader';

const styles = (theme) => ({
  container: {
    padding: '0 200px 50px 0',
  },
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
});

class Connectors extends Component {
  render() {
    const { classes, t } = this.props;
    return (
      <div className={classes.container}>
        <IngestionMenu/>
        <BreadcrumbHeader
          path={[
            { text: t('Data') },
            { text: t('Connectors') },
          ]}
        >
          <div className={ classes.header }>{t('Connectors')}</div>
        </BreadcrumbHeader>
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
