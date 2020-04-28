import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixObjectNotesCards, {
  stixObjectNotesCardsQuery,
} from './StixObjectNotesCards';
import { QueryRenderer } from '../../../../relay/environment';

class StixObjectNotes extends Component {
  render() {
    const {
      t, entityId, inputType, marginTop,
    } = this.props;
    let filter = 'knowledgeContains';
    if (inputType === 'observableRefs') {
      filter = 'observablesContains';
    }
    return (
      <QueryRenderer
        query={stixObjectNotesCardsQuery}
        variables={{
          filters: [{ key: filter, values: [entityId] }],
          first: 200,
          orderBy: 'created',
          orderMode: 'desc',
        }}
        render={({ props }) => {
          if (props) {
            return (
              <StixObjectNotesCards
                entityId={entityId}
                inputType={inputType}
                data={props}
                marginTop={marginTop}
              />
            );
          }
          return (
            <div style={{ height: '100%', marginTop: marginTop || 40 }}>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Notes about this entity')}
              </Typography>
            </div>
          );
        }}
      />
    );
  }
}

StixObjectNotes.propTypes = {
  t: PropTypes.func,
  entityId: PropTypes.string,
  inputType: PropTypes.string,
  marginTop: PropTypes.number,
};

export default inject18n(StixObjectNotes);
