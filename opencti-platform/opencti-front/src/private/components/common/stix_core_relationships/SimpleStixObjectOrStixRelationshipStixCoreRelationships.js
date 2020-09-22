import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines, {
  simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery,
} from './SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
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
          <ListLines
            dataColumns={dataColumns}
            secondaryAction={true}
            noHeaders={true}
            noPadding={true}
            noBottomPadding={true}
          >
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
                return <div />;
              }}
            />
          </ListLines>
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
