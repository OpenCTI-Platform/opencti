import React, { FunctionComponent } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { Checkbox, Drawer, IconButton, List, ListItem, ListItemText, ListSubheader, Tooltip } from '@mui/material';
import { makeStyles } from '@mui/styles';
import { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import { QueryRenderer } from 'src/relay/environment';
import useAuth from 'src/utils/hooks/useAuth';
import { FilterOffOutline } from 'mdi-material-ui';
import { stixCyberObservablesLinesSubTypesQuery } from '../stix_cyber_observables/StixCyberObservablesLines';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
  },
  item: {
    padding: '0 0 0 6px',
  },
  toolbar: theme.mixins.toolbar,
}));

interface FinancialDataRightBarProps {
  handleToggle: (type: string) => void,
  handleClear: () => void,
  types?: string[],
}

export interface StixCyberObservablesLinesSubTypes {
  subTypes: {
    edges: {
      node: {
        id: string,
        label: string,
      }
    }[]
  }
}

const FinancialDataRightBar: FunctionComponent<FinancialDataRightBarProps> = ({
  handleToggle,
  handleClear,
  types = [],
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { bannerSettings } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  return (
    <Drawer
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      PaperProps={{
        style: {
          paddingTop: bannerSettings.bannerHeight,
          paddingBottom: bannerSettings.bannerHeight,
        },
      }}
    >
      <div className={classes.toolbar} />
      <QueryRenderer
        query={stixCyberObservablesLinesSubTypesQuery}
        variables={{ type: 'Stix-Cyber-Observable', search: 'Financial' }}
        render={({ props }: { props: StixCyberObservablesLinesSubTypes }) => {
          if (props && props.subTypes) {
            const subTypesEdges = [...props.subTypes.edges];
            const translatedOrderedList = subTypesEdges
              .sort(({ node: a }, { node: b }) => (a.label < b.label ? -1 : 1))
              .map(({ node }) => ({ ...node, tlabel: t_i18n(`entity_${node.label}`) }));
            return (
              <List
                style={{ marginTop: settingsMessagesBannerHeight }}
                subheader={
                  <ListSubheader component="div">
                    {t_i18n('Financial types')}
                    <Tooltip title={t_i18n('Clear filters')}>
                      <IconButton
                        onClick={handleClear}
                        disabled={types.length === 0}
                        color="primary"
                        size="large"
                      >
                        <FilterOffOutline fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </ListSubheader>
                }
              >
                {translatedOrderedList.map((subType) => (
                  <ListItem
                    key={subType.id}
                    dense={true}
                    onClick={() => handleToggle(subType.label)}
                    classes={{ root: classes.item }}
                  >
                    <Checkbox
                      checked={types.includes(subType.label)}
                      disableRipple={true}
                      size="small"
                    />
                    <ListItemText primary={subType.tlabel} />
                  </ListItem>
                ))}
              </List>
            );
          }
          return <div />;
        }}
      />
    </Drawer>
  );
};

export default FinancialDataRightBar;
