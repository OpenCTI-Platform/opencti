import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import CardActions from '@material-ui/core/CardActions';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import { WbIridescent } from '@material-ui/icons';
import { commitMutation, QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import SettingsMenu from './SettingsMenu';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  card: {
    width: '100%',
    height: '100%',
    position: 'relative',
  },
  cardContent: {
    paddingTop: 0,
    marginBottom: 40,
  },
  actions: {
    position: 'absolute',
    bottom: 0,
  },
});

const inferencesQuery = graphql`
  query InferencesQuery {
    inferences {
      id
      name
      rule
      description
      enabled
    }
  }
`;

const inferencesEnableMutation = graphql`
  mutation InferencesEnableMutation($id: ID!) {
    inferenceEnable(id: $id) {
      id
      name
      rule
      description
      enabled
    }
  }
`;

const inferencesDisableMutation = graphql`
  mutation InferencesDisableMutation($id: ID!) {
    inferenceDisable(id: $id) {
      id
      name
      rule
      description
      enabled
    }
  }
`;

class Inferences extends Component {
  handleToggle(id, enabled) {
    commitMutation({
      mutation: enabled ? inferencesDisableMutation : inferencesEnableMutation,
      variables: { id },
    });
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div className={classes.container}>
        <SettingsMenu />
        <Typography variant="h1" gutterBottom={true}>
          {t('Inference rules')}
        </Typography>
        <Grid container={true} spacing={3}>
          <QueryRenderer
            query={inferencesQuery}
            render={({ props }) => {
              if (props && props.inferences) {
                return props.inferences.map((inference) => (
                  <Grid key={inference.id} item={true} lg={6} xs={12}>
                    <Card classes={{ root: classes.card }}>
                      <CardHeader
                        avatar={<WbIridescent />}
                        title={inference.name}
                      />
                      <CardContent classes={{ root: classes.cardContent }}>
                        <Typography
                          variant="body2"
                          color="textSecondary"
                          component="p"
                        >
                          {inference.description}
                        </Typography>
                        <pre>
                          {inference.rule}
                        </pre>
                      </CardContent>
                      <CardActions disableSpacing className={classes.actions}>
                        <FormControlLabel
                          control={
                            <Switch
                              onChange={this.handleToggle.bind(
                                this,
                                inference.id,
                                inference.enabled,
                              )}
                              checked={inference.enabled}
                            />
                          }
                          label={t('Enabled')}
                          labelPlacement="end"
                        />
                      </CardActions>
                    </Card>
                  </Grid>
                ));
              }
              return <div> &nbsp; </div>;
            }}
          />
        </Grid>
      </div>
    );
  }
}

Inferences.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(Inferences);
