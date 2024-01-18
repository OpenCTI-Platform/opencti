import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import { StixCoreObjectSubscribersCountQuery$data } from './__generated__/StixCoreObjectSubscribersCountQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import Drawer, { DrawerVariant } from '../drawer/Drawer';
import { computeLink } from '../../../../utils/Entity';

// region types
interface ContainerHeaderSharedProps {
  elementId: string;
}
// endregion

const stixCoreObjectSubscribersCountQuery = graphql`
  query StixCoreObjectSubscribersCountQuery($filters: FilterGroup, $includeAuthorities: Boolean, $search: String) {
    triggersKnowledgeCount(filters: $filters, includeAuthorities: $includeAuthorities, search: $search)
    triggersKnowledge(filters: $filters, includeAuthorities: $includeAuthorities, search: $search) {
      edges {
        node {
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
          style={{ cursor: hasSetAccess ? 'pointer' : 'default', marginRight: 10 }}
          sx={!hasSetAccess ? {
            '&.MuiButtonBase-root:hover': {
              bgcolor: 'transparent',
            },
          } : undefined}
          onClick={() => (hasSetAccess ? setDisplaySubscribers(true) : null)}
          disableRipple={!hasSetAccess}
        >
          {triggersKnowledgeCount ?? '0'} {t_i18n('subscribers')}
        </Button>
        {hasSetAccess && (
          <Drawer
            open={displaySubscribers}
            variant={DrawerVariant.create}
            title={t_i18n('Subscribers')}
            onClose={() => setDisplaySubscribers(false)}
          >
            <List>
              {triggersKnowledge?.edges.map((triggerNode) => (
                <>
                  {triggerNode?.node?.recipients?.map((recipient) => (
                    <ListItem
                      key={recipient.id}
                      divider={true}
                      button={true}
                      component={Link}
                      to={`${computeLink(recipient)}`}
                    >
                      <ListItemIcon>
                        <ItemIcon type={recipient.entity_type}/>
                      </ListItemIcon>
                      <ListItemText
                        primary={recipient.name}
                        secondary={recipient.entity_type}
                      />
                    </ListItem>
                  ))}
                </>
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
