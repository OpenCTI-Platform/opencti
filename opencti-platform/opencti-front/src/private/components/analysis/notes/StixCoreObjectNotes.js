import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreObjectNotesCards, {
  stixCoreObjectNotesCardsQuery,
} from './StixCoreObjectNotesCards';
import { QueryRenderer } from '../../../../relay/environment';

class StixCoreObjectNotes extends Component {
  render() {
    const {
      t, stixCoreObjectId, inputType, marginTop,
    } = this.props;
    return (
      <QueryRenderer
        query={stixCoreObjectNotesCardsQuery}
        variables={{ id: stixCoreObjectId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreObjectNotesCards
                stixCoreObjectId={stixCoreObjectId}
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

StixCoreObjectNotes.propTypes = {
  t: PropTypes.func,
  stixCoreObjectId: PropTypes.string,
  inputType: PropTypes.string,
  marginTop: PropTypes.number,
};

export default inject18n(StixCoreObjectNotes);
