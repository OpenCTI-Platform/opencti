import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import { compose } from 'ramda';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines, {
  simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery,
} from './SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines';
import { QueryRenderer } from '../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: 0,
    borderRadius: 4,
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
        width: '12%',
        isSortable: true,
      },
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      created_at: {
        label: 'Platform creation date',
        width: '12%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence',
        width: '12%',
        isSortable: false,
      },
      markings: {
        label: 'Markings',
        isSortable: false,
        width: '12%',
      },
    };
    const paginationOptions = {
      fromOrToId: stixObjectOrStixRelationshipId,
      relationship_type: relationshipType || 'stix-core-relationship',
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <>
        <Typography variant="h4">
          {t('Latest created relationships')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
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
                      <ListItemIcon classes={{ root: classes.itemIcon }}>
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
              );
            }}
          />
        </Paper>
      </>
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
  navigate: PropTypes.func,
  paginationOptions: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(SimpleStixObjectOrStixRelationshipStixCoreRelationships);
