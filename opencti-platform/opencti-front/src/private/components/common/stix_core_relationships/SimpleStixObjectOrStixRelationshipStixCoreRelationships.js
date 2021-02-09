import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { DescriptionOutlined } from '@material-ui/icons';
import ListItemText from '@material-ui/core/ListItemText';
import inject18n from '../../../../components/i18n';
import SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines, {
  simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery,
} from './SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines';
import { QueryRenderer } from '../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
});

class SimpleStixObjectOrStixRelationshipStixCoreRelationships extends Component {
  render() {
    const {
      stixObjectOrStixRelationshipId,
      stixObjectOrStixRelationshipLink,
      relationshipType,
      classes,
      t,
    } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Relationship type',
        width: '15%',
        isSortable: true,
      },
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '35%',
        isSortable: true,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence',
        isSortable: false,
      },
    };
    const paginationOptions = {
      elementId: stixObjectOrStixRelationshipId,
      relationship_type: relationshipType || 'stix-core-relationship',
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Latest created relationships')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={
              simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery
            }
            variables={{ count: 8, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines
                    stixObjectOrStixRelationshipId={
                      stixObjectOrStixRelationshipId
                    }
                    stixObjectOrStixRelationshipLink={
                      stixObjectOrStixRelationshipLink
                    }
                    data={props}
                    container={props.container}
                    dataColumns={dataColumns}
                    initialLoading={false}
                    paginationOptions={paginationOptions}
                  />
                );
              }
              return (
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon
                        classes={{ root: classes.itemIconDisabled }}
                      >
                        <DescriptionOutlined />
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
              );
            }}
          />
        </Paper>
      </div>
    );
  }
}

SimpleStixObjectOrStixRelationshipStixCoreRelationships.propTypes = {
  stixObjectOrStixRelationshipId: PropTypes.string,
  stixObjectOrStixRelationshipLink: PropTypes.string,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
  paginationOptions: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(SimpleStixObjectOrStixRelationshipStixCoreRelationships);
