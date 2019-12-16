import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixRelationStixRelationsLines, {
  stixRelationStixRelationsLinesQuery,
} from './StixRelationStixRelationsLines';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '3px 0 0 0',
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

class StixRelationStixRelations extends Component {
  render() {
    const {
      t, classes, entityId, relationType,
    } = this.props;
    const paginationOptions = {
      fromId: entityId,
      relationType,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <QueryRenderer
        query={stixRelationStixRelationsLinesQuery}
        variables={{ count: 25, ...paginationOptions }}
        render={({ props }) => {
          if (props) {
            return (
              <StixRelationStixRelationsLines
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
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon>
                        <Avatar classes={{ root: classes.avatarDisabled }}>
                          {i}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <span className="fakeItem" style={{ width: '80%' }} />
                        }
                        secondary={
                          <span className="fakeItem" style={{ width: '90%' }} />
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

StixRelationStixRelations.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationStixRelations);
