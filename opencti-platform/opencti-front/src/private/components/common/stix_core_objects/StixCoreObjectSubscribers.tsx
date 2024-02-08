import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { StixCoreObjectSubscribersCountQuery$data } from './__generated__/StixCoreObjectSubscribersCountQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import Drawer from '../drawer/Drawer';
import { computeLink } from '../../../../utils/Entity';
import type { Theme } from '../../../../components/Theme';

// region types
interface ContainerHeaderSharedProps {
  elementId: string;
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

const stixCoreObjectSubscribersCountQuery = graphql`
  query StixCoreObjectSubscribersCountQuery($filters: FilterGroup, $includeAuthorities: Boolean, $search: String) {
    triggersKnowledgeCount(filters: $filters, includeAuthorities: $includeAuthorities, search: $search)
    triggersKnowledge(filters: $filters, includeAuthorities: $includeAuthorities, search: $search) {
      edges {
        node {
          id
          recipients {
            name
            id
            entity_type
          }
        }
      }
    }
  }
`;

const StixCoreObjectSubscribers: FunctionComponent<ContainerHeaderSharedProps> = ({
  elementId,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [displaySubscribers, setDisplaySubscribers] = useState(false);
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const render = ({ triggersKnowledgeCount, triggersKnowledge }: StixCoreObjectSubscribersCountQuery$data) => {
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
                        <ItemIcon type={recipient.entity_type}/>
                      </ListItemIcon>
                      <ListItemText primary={recipient.name} />
                      <ListItemIcon classes={{ root: classes.goIcon }}>
                        <KeyboardArrowRightOutlined/>
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
  return (
    <QueryRenderer
      query={stixCoreObjectSubscribersCountQuery}
      variables={{
        includeAuthorities: true,
        filters: {
          mode: 'and',
          filters: [
            {
              key: ['filters'],
              values: [elementId],
              operator: 'match',
              mode: 'or',
            },
            {
              key: ['instance_trigger'],
              values: [true.toString()],
              operator: 'eq',
              mode: 'or',
            },
          ],
          filterGroups: [],
        },
      }}
      render={(result: { props: StixCoreObjectSubscribersCountQuery$data }) => {
        if (result.props) {
          return render(result.props);
        }
        return <div />;
      }}
    />
  );
};

export default StixCoreObjectSubscribers;
