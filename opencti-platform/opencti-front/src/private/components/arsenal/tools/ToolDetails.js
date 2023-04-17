import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
    margin: '0 5px 5px 0',
  },
});

class ToolDetailsComponent extends Component {
  render() {
    const { t, classes, tool } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={tool.description} limit={400} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Tool version')}
              </Typography>
              {tool.tool_version}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Tool types')}
              </Typography>
              {tool.tool_types && (
                <List>
                  {tool.tool_types.map((tool_type) => (
                    <ListItem key={tool_type} dense={true} divider={true}>
                      <ListItemText
                        primary={
                          <ItemOpenVocab
                            type="tool_types_ov"
                            value={tool_type}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
              <StixCoreObjectKillChainPhasesView killChainPhasesEdges={tool.killChainPhases.edges} />
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

ToolDetailsComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ToolDetails = createFragmentContainer(ToolDetailsComponent, {
  tool: graphql`
    fragment ToolDetails_tool on Tool {
      id
      description
      tool_version
      tool_types
      killChainPhases {
        edges {
          node {
            id
            entity_type
            kill_chain_name
            phase_name
            x_opencti_order
          }
        }
      }
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(ToolDetails);
