import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import StixCyberObservableRelationCreationFromEntity from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipCreationFromEntity';
import StixCyberObservableObservablesLines, {
  stixCyberObservableObservablesLinesQuery,
} from './StixCyberObservableObservablesLines';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class StixCyberObservableLinks extends Component {
  render() {
    const { stixCyberObservableId, t, stixCyberObservableType } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Relation',
        width: '15%',
        isSortable: true,
      },
      entity_type: {
        label: 'Entity type',
        width: '15%',
        isSortable: false,
      },
      observable_value: {
        label: 'Observable value',
        width: '35%',
        isSortable: false,
      },
      start_time: {
        label: 'First obs.',
        width: '15%',
        isSortable: false,
      },
      stop_time: {
        label: 'Last obs.',
        isSortable: false,
      },
    };
    const paginationOptions = {
      elementId: stixCyberObservableId,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <div>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Linked observables')}
        </Typography>
        <StixCyberObservableRelationCreationFromEntity
          paginationOptions={paginationOptions}
          entityId={stixCyberObservableId}
          isRelationReversed={false}
          variant="inLine"
          entityType={stixCyberObservableType}
        />
        <div className="clearfix" />
        <ListLines
          dataColumns={dataColumns}
          displayImport={true}
          secondaryAction={true}
          noHeaders={true}
        >
          <QueryRenderer
            query={stixCyberObservableObservablesLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => (
              <StixCyberObservableObservablesLines
                entityId={stixCyberObservableId}
                dataColumns={dataColumns}
                data={props}
                paginationOptions={paginationOptions}
                initialLoading={props === null}
                displayRelation={true}
              />
            )}
          />
        </ListLines>
      </div>
    );
  }
}

StixCyberObservableLinks.propTypes = {
  stixCyberObservableId: PropTypes.string,
  stixCyberObservableType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(StixCyberObservableLinks);
