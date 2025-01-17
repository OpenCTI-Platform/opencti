import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Tooltip from '@mui/material/Tooltip';
import { ToolDetails_tool$key } from '@components/arsenal/tools/__generated__/ToolDetails_tool.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { truncate } from '../../../../utils/String';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';

const ToolDetailsFragment = graphql`
 fragment ToolDetails_tool on Tool {
   id
   description
   tool_version
   tool_types
   killChainPhases {
     id
     entity_type
     kill_chain_name
     phase_name
     x_opencti_order
   }
 }
`;

interface ToolDetailsProps {
  tools: ToolDetails_tool$key;
}

const ToolDetails: FunctionComponent<ToolDetailsProps> = ({ tools }) => {
  const { t_i18n } = useFormatter();
  const tool = useFragment(
    ToolDetailsFragment,
    tools,
  );
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper
        className={'paper-for-grid'}
        variant="outlined"
        style={{
          marginTop: '8px',
          padding: '15px',
          borderRadius: 4,
        }}
      >
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={tool.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Tool version')}
            </Typography>
            <FieldOrEmpty source={tool.tool_version}>
              <Tooltip title={tool.tool_version}>
                {truncate(tool.tool_version, 20)}
              </Tooltip>
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Tool types')}
            </Typography>
            {(tool.tool_types && tool.tool_types.length > 0) ? (
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
            ) : ('-')}
            <StixCoreObjectKillChainPhasesView killChainPhases={tool.killChainPhases ?? []} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ToolDetails;
