import React from 'react';
import * as R from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Refresh } from '@mui/icons-material';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';

export const stixCoreObjectEnrollPlaybookLinesQuery = graphql`
  query StixCoreObjectEnrollPlaybookLinesQuery($id: String!) {
    playbooksForEntity(id: $id) {
      ...StixCoreObjectEnrollPlaybookLines_playbooksForEntity
    }
  }
`;

const stixCoreObjectEnrollPlaybookLinesPlaybookExecute = graphql`
  mutation StixCoreObjectEnrollPlaybookLinesMutation($id: ID!, $entityId: String!) {
      playbookExecute(id: $id, entityId: $entityId)
  }
`;

const styles = (theme) => ({
  noResult: {
    color: theme.palette.text.primary,
    fontSize: 15,
  },
  gridContainer: {
    marginBottom: 20,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
  tooltip: {
    maxWidth: 600,
  },
});

const StixCoreObjectEnrollPlaybook = ({
  stixCoreObject,
  playbooksForEntity,
  relay,
  classes,
  t,
  nsdt,
}) => {
  const { id } = stixCoreObject;
  const file = stixCoreObject.importFiles && stixCoreObject.importFiles.edges.length > 0
    ? stixCoreObject.importFiles.edges[0].node
    : null;
  return (
    <List>
      {playbooksForEntity.length > 0 ? (
        playbooksForEntity.map((playbook) => {
          return (
            <div key={playbook.id}>
              <ListItem
                divider={true}
                classes={{ root: classes.item }}
                button={true}
              >
                <ListItemIcon>
                  <ItemIcon type="playbook" color='#4caf50' />
                </ListItemIcon>
                <ListItemText primary={playbook.name} />
                <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                  <ListItemSecondaryAction style={{ right: 0 }}>
                    <Tooltip title={t('Trigger this playbook now')}>
                      <IconButton
                        onClick={}
                        size="large"
                      >
                        <Refresh />
                      </IconButton>
                    </Tooltip>
                  </ListItemSecondaryAction>
                </Security>
              </ListItem>
            </div>
          );
        })
      ) : (
        <div className={classes.noResult}>
          {t('No available playbooks for this entity')}
        </div>
      )}
    </List>
  );
};

const StixCoreObjectEnrollPlaybookLinesFragment = createRefetchContainer(
  StixCoreObjectEnrollPlaybook,
  {
    playbooksForEntity: graphql`
      fragment StixCoreObjectEnrollPlaybookLines_playbooksForEntity on Playbook
      @relay(plural: true) {
        id
        name
        description
      }
    `,
  },
  stixCoreObjectEnrollPlaybookLinesQuery,
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectEnrollPlaybookLinesFragment);
