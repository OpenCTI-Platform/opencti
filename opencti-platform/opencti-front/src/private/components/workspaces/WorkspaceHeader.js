import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import WorkspacePopover from './WorkspacePopover';
import Security, { EXPLORE_EXUPDATE } from '../../../utils/Security';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
    float: 'right',
    overflowX: 'hidden',
  },
  alias: {
    marginRight: 7,
  },
  aliasInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class WorkspaceHeaderComponent extends Component {
  render() {
    const { classes, workspace } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {workspace.name}
        </Typography>
        <div className={classes.popover}>
          <Security needs={[EXPLORE_EXUPDATE]}>
            <WorkspacePopover workspaceId={workspace.id}
              workspaceType={workspace.workspace_type}/>
          </Security>
        </div>
        <div className={classes.marking}>
          {pathOr([], ['markingDefinitions', 'edges'], workspace).map(
            (markingDefinition) => (
              <ItemMarking
                key={markingDefinition.node.id}
                label={markingDefinition.node.definition}
              />
            ),
          )}
        </div>
        <div className="clearfix" />
      </div>
    );
  }
}

WorkspaceHeaderComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const WorkspaceHeader = createFragmentContainer(WorkspaceHeaderComponent, {
  workspace: graphql`
    fragment WorkspaceHeader_workspace on Workspace {
      id
      workspace_type
      name
      markingDefinitions {
        edges {
          node {
            id
            definition
          }
        }
      }
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(WorkspaceHeader);
