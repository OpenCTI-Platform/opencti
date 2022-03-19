import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import TasksList, { tasksListQuery } from './tasks/TasksList';
import Loader from '../../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class Tasks extends Component {
  render() {
    const { classes, t } = this.props;
    const optionsInProgress = {
      count: 50,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters: [{ key: 'completed', values: ['false'] }],
    };
    const optionsFinished = {
      count: 50,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters: [{ key: 'completed', values: ['true'] }],
    };
    return (
      <div className={classes.container}>
        <Typography variant="h4" gutterBottom={true}>
          {t('In progress tasks')}
        </Typography>
        <QueryRenderer
          query={tasksListQuery}
          variables={optionsInProgress}
          render={({ props }) => {
            if (props) {
              return <TasksList data={props} options={optionsInProgress} />;
            }
            return <Loader variant="inElement" />;
          }}
        />
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 35 }}>
          {t('Completed tasks')}
        </Typography>
        <QueryRenderer
          query={tasksListQuery}
          variables={optionsFinished}
          render={({ props }) => {
            if (props) {
              return <TasksList data={props} options={optionsFinished} />;
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
    );
  }
}

Tasks.propTypes = {
  connector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(Tasks);
