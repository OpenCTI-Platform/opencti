import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import React, { FunctionComponent } from 'react';
import { makeStyles } from '@mui/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  killChainPhaseItem: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
}));

interface StixCoreObjectKillChainPhasesViewProps {
  killChainPhasesEdges: ReadonlyArray<{ node: {
    entity_type: string;
    id: string;
    kill_chain_name: string;
    phase_name: string;
    x_opencti_order: number | null;
  };
  }>;
  firstLine?: boolean,
}

const StixCoreObjectKillChainPhasesView: FunctionComponent<StixCoreObjectKillChainPhasesViewProps> = ({ killChainPhasesEdges, firstLine }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <div>
      <Typography variant="h3" gutterBottom={true} style={firstLine ? undefined : { marginTop: 20 }}>
        {t('Kill chain phases')}
      </Typography>
      {killChainPhasesEdges.length > 0
        ? <List>
          {killChainPhasesEdges.map((killChainPhaseEdge) => {
            const killChainPhase = killChainPhaseEdge.node;
            return (
              <ListItem
                key={killChainPhase.phase_name}
                dense={true}
                divider={true}
                classes={{ root: classes.killChainPhaseItem }}
              >
                <ListItemIcon>
                  <ItemIcon type={killChainPhase.entity_type}/>
                </ListItemIcon>
                <ListItemText primary={killChainPhase.phase_name}/>
              </ListItem>
            );
          })}
          </List>
        : ('-')
      }
    </div>
  );
};

export default StixCoreObjectKillChainPhasesView;
