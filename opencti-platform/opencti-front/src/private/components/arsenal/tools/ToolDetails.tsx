import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Grid from '@mui/material/Grid';
import Tooltip from '@mui/material/Tooltip';
import { ToolDetails_tool$key } from '@components/arsenal/tools/__generated__/ToolDetails_tool.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { truncate } from '../../../../utils/String';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

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
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={tool.description} limit={400} />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Tool version')}
            </Label>
            <FieldOrEmpty source={tool.tool_version}>
              <Tooltip title={tool.tool_version}>
                <span>{truncate(tool.tool_version, 20)}</span>
              </Tooltip>
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Tool types')}
            </Label>
            {(tool.tool_types && tool.tool_types.length > 0) ? (
              <List>
                {tool.tool_types.map((tool_type) => (
                  <ListItem key={tool_type} dense={true} divider={true}>
                    <ListItemText
                      primary={(
                        <ItemOpenVocab
                          type="tool_types_ov"
                          value={tool_type}
                        />
                      )}
                    />
                  </ListItem>
                ))}
              </List>
            ) : ('-')}
            <StixCoreObjectKillChainPhasesView killChainPhases={tool.killChainPhases ?? []} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default ToolDetails;
