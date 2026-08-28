import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipExternalReferencesLines, { stixCoreRelationshipExternalReferencesLinesQuery } from './StixCoreRelationshipExternalReferencesLines';
import Card from '../../../../components/common/card/Card';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

const StixCoreRelationshipExternalReferences = (props) => {
  const { t_i18n } = useFormatter();
  const { classes, stixCoreRelationshipId } = props;
  return (
    <QueryRenderer
      query={stixCoreRelationshipExternalReferencesLinesQuery}
      variables={{ id: stixCoreRelationshipId, count: 200 }}
      render={({ props }) => {
        if (props) {
          return (
            <StixCoreRelationshipExternalReferencesLines
              stixCoreRelationshipId={stixCoreRelationshipId}
              data={props}
            />
          );
        }
        return (
          <div style={{ height: '100%' }}>
            <Card title={t_i18n('External references')}>
              <List>
                {Array.from(Array(5), (e, i) => (
                  <ListItem
                    key={i}
                    dense={true}
                    divider={true}

                  >
                    <ListItemIcon>
                      <Avatar classes={{ root: classes.avatarDisabled }}>
                        {i}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                          style={{ marginBottom: 10 }}
                        />
                      )}
                      secondary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                        />
                      )}
                    />
                  </ListItem>
                ))}
              </List>
            </Card>
          </div>
        );
      }}
    />
  );
};

StixCoreRelationshipExternalReferences.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
};

export default withStyles(styles)(StixCoreRelationshipExternalReferences);
