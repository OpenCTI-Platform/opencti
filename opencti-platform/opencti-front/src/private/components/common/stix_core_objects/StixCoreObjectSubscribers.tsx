import React, { FunctionComponent, useState } from 'react';
import Button from '@mui/material/Button';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import {
  stixCoreObjectTriggersUtilsPaginationQuery$data,
  stixCoreObjectTriggersUtilsPaginationQuery as TriggerQuery,
} from '@components/common/stix_core_objects/__generated__/stixCoreObjectTriggersUtilsPaginationQuery.graphql';
import { stixCoreObjectTriggersFragment } from '@components/common/stix_core_objects/stixCoreObjectTriggersUtils';
import { useRefetchableFragment } from 'react-relay';
import { stixCoreObjectTriggersUtils_triggers$key as FragmentKey } from '@components/common/stix_core_objects/__generated__/stixCoreObjectTriggersUtils_triggers.graphql';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import Drawer from '../drawer/Drawer';
import { computeLink } from '../../../../utils/Entity';
import type { Theme } from '../../../../components/Theme';

// region types
interface ContainerHeaderSharedProps {
  triggerData: stixCoreObjectTriggersUtilsPaginationQuery$data
}
// endregion

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

const StixCoreObjectSubscribers: FunctionComponent<ContainerHeaderSharedProps> = ({
  triggerData,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [displaySubscribers, setDisplaySubscribers] = useState(false);
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);

  const [{ triggersKnowledge, triggersKnowledgeCount }] = useRefetchableFragment<TriggerQuery, FragmentKey>(stixCoreObjectTriggersFragment, triggerData);

  return (
    <React.Fragment>
      <Button
        size="small"
        variant="text"
        color={hasSetAccess ? 'primary' : 'inherit'}
        style={{ cursor: hasSetAccess && triggersKnowledgeCount && triggersKnowledgeCount > 0 ? 'pointer' : 'default', marginRight: 10 }}
        sx={!hasSetAccess ? {
          '&.MuiButtonBase-root:hover': {
            bgcolor: 'transparent',
          },
        } : undefined}
        onClick={() => (hasSetAccess && triggersKnowledgeCount && triggersKnowledgeCount > 0 ? setDisplaySubscribers(true) : null)}
        disableRipple={!hasSetAccess}
      >
        {triggersKnowledgeCount ?? '0'} {t_i18n('subscribers')}
      </Button>
      {hasSetAccess && (
        <Drawer
          open={displaySubscribers}
          title={t_i18n('Subscribers')}
          onClose={() => setDisplaySubscribers(false)}
        >
          <List>
            {triggersKnowledge?.edges.map((triggerEdge) => (
              <React.Fragment key={triggerEdge.node.id}>
                {triggerEdge.node.recipients?.map((recipient) => (
                  <ListItem
                    classes={{ root: classes.item }}
                    key={recipient.id}
                    divider={true}
                    button={true}
                    component={Link}
                    to={`${computeLink(recipient)}`}
                  >
                    <ListItemIcon classes={{ root: classes.itemIcon }}>
                      <ItemIcon type={recipient.entity_type} />
                    </ListItemIcon>
                    <ListItemText primary={recipient.name} />
                    <ListItemIcon classes={{ root: classes.goIcon }}>
                      <KeyboardArrowRightOutlined />
                    </ListItemIcon>
                  </ListItem>
                ))}
              </React.Fragment>
            ))}
          </List>
        </Drawer>
      )}
    </React.Fragment>
  );
};

export default StixCoreObjectSubscribers;
