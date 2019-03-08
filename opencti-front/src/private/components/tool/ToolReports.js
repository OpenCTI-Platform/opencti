import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import ToolHeader from './ToolHeader';
import EntityReports from '../report/EntityReports';

const styles = theme => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class ToolReportsComponent extends Component {
  render() {
    const { classes, tool } = this.props;
    return (
      <div className={classes.container}>
        <ToolHeader tool={tool}/>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={tool.id}/>
        </Paper>
      </div>
    );
  }
}

ToolReportsComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ToolReports = createFragmentContainer(ToolReportsComponent, {
  tool: graphql`
      fragment ToolReports_tool on Tool {
          id
          ...ToolHeader_tool
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ToolReports);
