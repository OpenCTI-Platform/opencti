import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import type { Theme } from '../../../../components/Theme';
import Label from '../../../../components/common/label/Label';

interface StixCoreObjectKillChainPhasesViewProps {
  killChainPhases?: ReadonlyArray<{
    entity_type: string;
    id: string;
    kill_chain_name: string;
    phase_name: string;
    x_opencti_order?: number | null;
  }> | null;
  firstLine?: boolean;
  displayIcon?: boolean;
}

const StixCoreObjectKillChainPhasesView = ({
  killChainPhases,
  firstLine,
  displayIcon = false,
}: StixCoreObjectKillChainPhasesViewProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div>
      <Label sx={firstLine ? undefined : { marginTop: 2 }}>
        {t_i18n('Kill chain phases')}
      </Label>
      <FieldOrEmpty source={killChainPhases}>
        <List sx={{ py: 0 }}>
          {(killChainPhases ?? []).map((killChainPhase) => {
            return (
              <ListItem
                key={killChainPhase.phase_name}
                dense={true}
                divider={true}
                sx={{
                  paddingLeft: 0,
                  transition: 'background-color 0.1s ease',
                  '&:hover': {
                    background: 'rgba(0, 0, 0, 0.1)',
                  },
                }}
              >
                {displayIcon && (
                  <ListItemIcon>
                    <ItemIcon type={killChainPhase.entity_type} />
                  </ListItemIcon>
                )}
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
