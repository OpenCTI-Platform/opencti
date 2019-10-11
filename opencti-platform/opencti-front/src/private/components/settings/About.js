import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { Box } from '@material-ui/core';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';

const styles = () => ({
  panel: {
    width: '50%',
    margin: '0 auto',
    marginBottom: 30,
    padding: '20px 20px 20px 20px',
    textAlign: 'left',
    borderRadius: 6,
  },
});

const aboutQuery = graphql`
  query AboutQuery {
    info {
      app_version
      grakn_version
      elasticsearch_version
      rabbitmq_version
      redis_version
    }
  }
`;

const versionInfo = (label, version) => ({ label, version });

class About extends Component {
  render() {
    const { classes, t } = this.props;
    return (
      <QueryRenderer
        query={aboutQuery}
        render={({ props }) => {
          const versions = [];
          if (props && props.info) {
            const { info } = props;
            versions.push(versionInfo('OpenCTI version:', info.app_version));
            versions.push(versionInfo('Grakn version:', info.grakn_version));
            versions.push(versionInfo('Elasticsearch version:', info.elasticsearch_version));
            versions.push(versionInfo('Redis version:', info.redis_version));
            versions.push(versionInfo('RabbitMQ version:', info.rabbitmq_version));
          }
          return (
            <Box>
              <Paper classes={{ root: classes.panel }} elevation={2}>
                <Typography variant="h1" gutterBottom={true}>
                  {t('About')}
                </Typography>
                { versions.length > 0
                  && <List>
                    {versions.map(version => (
                      <ListItem key={version.label} divider>
                        <ListItemText primary={t(version.label)} secondary={version.version} />
                      </ListItem>
                    ))}
                  </List>
                }
              </Paper>
            </Box>
          );
        }}
      />
    );
  }
}

About.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(About);
