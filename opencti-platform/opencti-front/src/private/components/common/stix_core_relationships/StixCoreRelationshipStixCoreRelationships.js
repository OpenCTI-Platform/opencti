import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipStixCoreRelationshipsLines, {
  stixCoreRelationshipStixCoreRelationshipsLinesQuery,
} from './StixCoreRelationshipStixCoreRelationshipsLines';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
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

class StixCoreRelationshipStixCoreRelationships extends Component {
  render() {
    const { t, classes, entityId, relationshipType } = this.props;
    const paginationOptions = {
      elementId: entityId,
      relationship_type: relationshipType,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <QueryRenderer
        query={stixCoreRelationshipStixCoreRelationshipsLinesQuery}
        variables={{ count: 25, ...paginationOptions }}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreRelationshipStixCoreRelationshipsLines
                entityId={entityId}
                data={props}
                paginationOptions={paginationOptions}
              />
            );
          }
          return (
            <div style={{ height: '100%' }}>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Linked entities')}
              </Typography>
              <div className="clearfix" />
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem key={i} divider={true} button={false}>
                      <ListItemIcon>
                        <Skeleton
                          animation="wave"
                          variant="circular"
                          width={30}
                          height={30}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        }
                        secondary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </div>
          );
        }}
      />
    );
  }
}

StixCoreRelationshipStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  relationshipType: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipStixCoreRelationships);
