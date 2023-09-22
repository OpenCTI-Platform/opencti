import React, { FunctionComponent } from 'react';
import { assoc, compose, prop, sortBy, toLower } from 'ramda';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { FilterOffOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { stixCyberObservablesLinesSubTypesQuery } from '../stix_cyber_observables/StixCyberObservablesLines';
import { Theme } from '../../../../components/Theme';
import { StixCyberObservablesLinesSubTypesQuery$data } from '../stix_cyber_observables/__generated__/StixCyberObservablesLinesSubTypesQuery.graphql';
import { vocabularyQuery } from '../../common/form/OpenVocabField';
import { OpenVocabFieldQuery$data } from '../../common/form/__generated__/OpenVocabFieldQuery.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    right: 0,
    padding: '0 0 20px 0',
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  drawerPaperExports: {
    minHeight: '100vh',
    width: 250,
    right: 310,
    padding: '0 0 20px 0',
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  item: {
    padding: '0 0 0 6px',
  },
  toolbar: theme.mixins.toolbar,
}));

interface IndicatorsRightBarProps {
  indicatorTypes: string[];
  observableTypes: string[];
  handleToggleIndicatorType: (name: string) => void;
  handleToggleObservableType: (name: string) => void;
  handleClearObservableTypes: () => void;
  openExports?: boolean;
}

const IndicatorsRightBar: FunctionComponent<IndicatorsRightBarProps> = ({
  indicatorTypes,
  observableTypes,
  handleToggleIndicatorType,
  handleToggleObservableType,
  handleClearObservableTypes,
  openExports,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  return (
    <Drawer
      variant="permanent"
      anchor="right"
      classes={{
        paper: openExports ? classes.drawerPaperExports : classes.drawerPaper,
      }}
      PaperProps={{
        style: { paddingTop: bannerHeightNumber + settingsMessagesBannerHeight },
      }}
    >
      <div className={classes.toolbar} />
      <QueryRenderer
        query={vocabularyQuery}
        variables={{
          category: 'pattern_type_ov',
          orderBy: 'name',
          orderMode: 'asc',
        }}
        render={({ props }: { props: OpenVocabFieldQuery$data }) => {
          const patternTypes = props?.vocabularies?.edges;
          return (
            <List
              subheader={
                <ListSubheader component="div">
                  {t('Pattern type')}
                </ListSubheader>
              }
            >
              {patternTypes
                && patternTypes.map((patternType) => (
                  <ListItem
                    key={patternType.node.id}
                    dense={true}
                    button={true}
                    onClick={() => handleToggleIndicatorType(patternType.node.name)
                    }
                    classes={{ root: classes.item }}
                  >
                    <Checkbox
                      checked={indicatorTypes.includes(patternType.node.name)}
                      disableRipple={true}
                      size="small"
                    />
                    <ListItemText primary={patternType.node.name} />
                  </ListItem>
                ))}
            </List>
          );
        }}
      />
      <QueryRenderer
        query={stixCyberObservablesLinesSubTypesQuery}
        variables={{ type: 'Stix-Cyber-Observable' }}
        render={({
          props,
        }: {
          props: StixCyberObservablesLinesSubTypesQuery$data;
        }) => {
          if (props && props.subTypes) {
            const subTypesEdges = props.subTypes.edges;
            const sortByLabel = sortBy(compose(toLower, prop('tlabel')));
            const translatedOrderedList = sortByLabel(
              subTypesEdges
                .map((n) => n.node)
                .map((n) => assoc('tlabel', t(`entity_${n.label}`), n)),
            );
            return (
              <List
                subheader={
                  <ListSubheader component="div">
                    {t('Observable type')}
                    <Tooltip title={t('Clear filters')}>
                      <IconButton
                        onClick={handleClearObservableTypes}
                        disabled={observableTypes.length === 0}
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
                    button={true}
                    onClick={() => handleToggleObservableType(subType.label)}
                    classes={{ root: classes.item }}
                  >
                    <Checkbox
                      checked={observableTypes.includes(subType.label)}
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

export default IndicatorsRightBar;
