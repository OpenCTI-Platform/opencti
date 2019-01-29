import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import ToolHeader from './ToolHeader';
import EntityReports from '../report/EntityReports';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ToolReportsComponent extends Component {
  render() {
    const { classes, tool } = this.props;
    return (
      <div className={classes.container}>
        <ToolHeader tool={tool}/>
        <div style={{ height: 20 }}/>
        <EntityReports entityId={tool.id}/>
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
