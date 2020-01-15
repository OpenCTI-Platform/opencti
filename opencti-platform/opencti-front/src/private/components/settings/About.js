import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import SettingsMenu from './SettingsMenu';
import Loader from '../../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  panel: {
    margin: '0 auto',
    marginBottom: 30,
    padding: '20px 20px 20px 20px',
    textAlign: 'left',
    borderRadius: 6,
  },
});

const aboutQuery = graphql`
  query AboutQuery {
    about {
      version
      dependencies {
        name
        version
      }
    }
  }
`;

class About extends Component {
  render() {
    const { classes, t } = this.props;
    return (
      <div className={classes.container}>
        <SettingsMenu />
        <QueryRenderer
          query={aboutQuery}
          render={({ props }) => {
            if (props) {
              const { version, dependencies } = props.about;
              return (
                <Paper classes={{ root: classes.panel }} elevation={2}>
                  <Typography variant="h1" gutterBottom={true}>
                    {t('OpenCTI version')} {version}
                  </Typography>
                  <br />
                  <Typography variant="h2" gutterBottom={true}>
                    <b>{t('Dependencies')}</b>
                  </Typography>
                  <List>
                    {dependencies.map((dep) => (
                      <ListItem key={dep.name} divider>
                        <ListItemText
                          primary={t(dep.name)}
                          secondary={dep.version}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

About.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(About);
