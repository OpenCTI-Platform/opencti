import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, assoc, mapObjIndexed, values,
} from 'ramda';
import { Formik, Field, Form } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Paper from '@material-ui/core/Paper';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../relay/environment';

const styles = () => ({
  container: {
    margin: 0,
  },
  panel: {
    width: '50%',
    margin: '0 auto',
    marginBottom: 30,
    padding: '20px 20px 20px 20px',
    textAlign: 'left',
    borderRadius: 6,
  },
});

const connectorsStatsQuery = graphql`
  query ConnectorsStatsQuery {
    connectorsStats {
      name
      messages
      messages_ready
      messages_unacknowledged
      consumers
      message_stats {
        deliver_details {
          rate
        }
      }
    }
  }
`;

class ConnectorsStats extends Component {
  constructor(props) {
    super(props);
    this.state = { refetch: false };
  }

  render() {
    const { classes, t } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={connectorsStatsQuery}
          variables={{}}
          render={({ props }) => {
            if (props) {
              const { connectorsStats } = props;
              return connectorsStats.map((connector) => {
                const connectorConfigTemplate = JSON.parse(
                  Buffer.from(connector.config_template, 'base64').toString(
                    'ascii',
                  ),
                );
                let config = map(
                  x => x.default,
                  connectorConfigTemplate.fields,
                );
                if (connector.config) {
                  config = JSON.parse(
                    Buffer.from(connector.config, 'base64').toString('ascii'),
                  );
                }
                const fields = values(
                  mapObjIndexed(
                    (value, key, obj) => assoc('name', key, value),
                    connectorConfigTemplate.fields,
                  ),
                );
                return (
                  <Paper
                    key={connector.identifier}
                    classes={{ root: classes.panel }}
                    elevation={2}
                  >
                    <Formik
                      enableReinitialize={true}
                      initialValues={config}
                      onSubmit={this.handleSubmit.bind(
                        this,
                        connector.identifier,
                      )}
                      render={({ submitForm, isSubmitting }) => (
                        <Form style={{ margin: '0 0 20px 0' }}>
                          <Typography
                            variant="h1"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {connectorConfigTemplate.name}
                          </Typography>
                          <Button
                            variant="outlined"
                            type="button"
                            color="secondary"
                            onClick={this.trigger.bind(
                              this,
                              connector.identifier,
                              config,
                            )}
                            disabled={isSubmitting}
                            classes={{ root: classes.button }}
                            size="small"
                            style={{ float: 'right' }}
                          >
                            {t('Force now')}
                          </Button>
                          <div className="clearfix" />
                          {fields.map((field) => {
                            if (field.type === 'select') {
                              return (
                                <Field
                                  key={field.name}
                                  name={field.name}
                                  component={Select}
                                  label={field.description}
                                  multiple={
                                    field.multiple ? field.multiple : false
                                  }
                                  fullWidth={true}
                                  inputProps={{
                                    name: field.name,
                                    id: field.name,
                                  }}
                                  containerstyle={{
                                    marginTop: 20,
                                    width: '100%',
                                  }}
                                >
                                  {field.options.map(option => (
                                    <MenuItem
                                      key={option.key}
                                      value={option.key}
                                    >
                                      {option.label}
                                    </MenuItem>
                                  ))}
                                </Field>
                              );
                            }
                            if (field.type === 'switch') {
                              return (
                                <Field
                                  key={field.name}
                                  name={field.name}
                                  component={Switch}
                                  label={field.description}
                                  containerstyle={{
                                    marginTop: 20,
                                    width: '100%',
                                  }}
                                />
                              );
                            }
                            return (
                              <Field
                                key={field.name}
                                name={field.name}
                                component={TextField}
                                label={field.description}
                                type="text"
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                            );
                          })}
                          <div style={{ marginTop: 20 }}>
                            <Button
                              variant="contained"
                              type="button"
                              color="primary"
                              onClick={submitForm}
                              disabled={isSubmitting}
                              classes={{ root: classes.button }}
                            >
                              {t('Update')}
                            </Button>
                          </div>
                        </Form>
                      )}
                    />
                  </Paper>
                );
              });
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

ConnectorsStats.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ConnectorsStats);
