import React, { useState } from 'react';
import * as R from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { PlayCircleOutlined } from '@mui/icons-material';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import Alert from '@mui/material/Alert';
import inject18n, { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { AUTOMATION } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

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
  itemIcon: {
    color: theme.palette.primary.main,
  },
  tooltip: {
    maxWidth: 600,
  },
});

const StixCoreObjectEnrollPlaybook = ({
  id,
  playbooksForEntity,
  classes,
}) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { t_i18n } = useFormatter();

  const askEnroll = (playbookId) => {
    setIsSubmitting(true);
    commitMutation({
      mutation: stixCoreObjectEnrollPlaybookLinesPlaybookExecute,
      variables: { id: playbookId, entityId: id },
      onCompleted: () => {
        setIsSubmitting(false);
        MESSAGING$.notifySuccess(t_i18n('Playbook successfully completed.'));
      },
    });
  };
  return (
    <>
      <Alert severity="info">
        {t_i18n('Listing playbooks with entry points manual or live trigger (events) and matching filters.')}
      </Alert>
      <List>
        {playbooksForEntity.length > 0 ? (
          playbooksForEntity.map((playbook) => {
            return (
              <div key={playbook.id}>
                <ListItem
                  divider={true}
                  classes={{ root: classes.item }}
                  secondaryAction={(
                    <Security needs={[AUTOMATION]}>
                      <div style={{ right: 0 }}>
                        <Tooltip title={t_i18n('Trigger this playbook now')}>
                          <IconButton
                            disabled={isSubmitting}
                            onClick={() => askEnroll(playbook.id)}
                          >
                            <PlayCircleOutlined />
                          </IconButton>
                        </Tooltip>
                      </div>
                    </Security>
                  )}
                >
                  <ListItemIcon classes={{ root: classes.itemIcon }}>
                    <ItemIcon type="Playbook" />
                  </ListItemIcon>
                  <ListItemText primary={playbook.name} />
                </ListItem>
              </div>
            );
          })
        ) : (
          <div className={classes.noResult}>
            {t_i18n('No available playbooks for this entity')}
          </div>
        )}
      </List>
    </>
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
