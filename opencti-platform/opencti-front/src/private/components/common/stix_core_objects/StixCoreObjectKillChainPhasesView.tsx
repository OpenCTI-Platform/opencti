import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { makeStyles, useTheme } from '@mui/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import type { Theme } from '../../../../components/Theme';
import Label from '../../../../components/common/label/Label';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  killChainPhases: ReadonlyArray<{
    entity_type: string;
    id: string;
    kill_chain_name: string;
    phase_name: string;
    x_opencti_order?: number | null;
  }>;
  firstLine?: boolean;
}

const StixCoreObjectKillChainPhasesView = ({
  killChainPhases,
  firstLine,
}: StixCoreObjectKillChainPhasesViewProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme<Theme>();
  return (
    <div>
      <Label sx={firstLine ? undefined : { marginTop: 2 }}>
        {t_i18n('Kill chain phases')}
      </Label>
      <FieldOrEmpty source={killChainPhases}>
        <List>
          {killChainPhases.map((killChainPhase) => {
            return (
              <ListItem
                key={killChainPhase.phase_name}
                dense={true}
                divider={true}
                classes={{ root: classes.killChainPhaseItem }}
              >
                <ListItemIcon>
                  <ItemIcon type={killChainPhase.entity_type} />
                </ListItemIcon>
                <ListItemText
                  primary={killChainPhase.phase_name}
                  secondary={<span style={{ color: theme.palette.text?.secondary }}>{killChainPhase.kill_chain_name}</span>}
                />
              </ListItem>
            );
          })}
        </List>
      </FieldOrEmpty>
    </div>
  );
};

export default StixCoreObjectKillChainPhasesView;
