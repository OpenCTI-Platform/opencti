import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';

const styles = () => ({
  container: {
    margin: 0,
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  gridContainer: {
    marginBottom: 20,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  chip: {
    fontSize: 12,
    height: 20,
    float: 'left',
    margin: '0 10px 10px 0',
  },
});

class ConnectorComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayUpdate: false,
    };
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false });
  }

  render() {
    const { classes, connector, t } = this.props;
    return (
      <div className={classes.container}>
        <div>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            {connector.name}
          </Typography>
          <div className={classes.popover}>&nbsp;</div>
          <div className="clearfix" />
        </div>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Basic information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Type')}
                  </Typography>
                  {connector.connector_type}
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Scope')}
                  </Typography>
                  {connector.connector_scope.map((scope) => (
                    <Chip
                      key={scope}
                      classes={{ root: classes.chip }}
                      label={scope}
                    />
                  ))}
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Active')}
                  </Typography>
                  <ItemBoolean
                    status={connector.active}
                    label={connector.active ? t('TRUE') : t('FALSE')}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Automatic')}
                  </Typography>
                  <ItemBoolean
                    status={connector.auto}
                    label={connector.auto ? t('TRUE') : t('FALSE')}
                  />
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('State')}
                  </Typography>
                  <pre>{connector.connector_state}</pre>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      </div>
    );
  }
}

ConnectorComponent.propTypes = {
  connector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Connector = createRefetchContainer(ConnectorComponent, {
  connector: graphql`
    fragment Connector_connector on Connector {
      id
      name
      active
      auto
      connector_type
      connector_scope
      connector_state
      updated_at
      created_at
      config {
        uri
        listen
        listen_exchange
        push
        push_exchange
      }
      works {
        id
        name
        user {
          name
        }
        timestamp
        status
        event_source_id
        received_time
        processed_time
        import_expected_number
        import_last_processed
        import_processed_number
        messages {
          timestamp
          message
          sequence
          source
        }
        errors {
          timestamp
          message
          sequence
          source
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Connector);
