import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipsExportsContent, { stixCoreRelationshipsExportsContentQuery } from './StixCoreRelationshipsExportsContent';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class StixCoreRelationshipsExports extends Component {
  render() {
    const { t, paginationOptions, open, handleToggle, exportContext } = this.props;
    return (
      <Drawer
        open={open}
        onClose={handleToggle.bind(this)}
        title={t('Exports list')}
        size="medium"
      >
        <QueryRenderer
          query={stixCoreRelationshipsExportsContentQuery}
          variables={{ count: 25, exportContext }}
          render={({ props }) => (
            <StixCoreRelationshipsExportsContent
              handleToggle={handleToggle.bind(this)}
              data={props}
              paginationOptions={paginationOptions}
              exportContext={exportContext}
              isOpen={open}
            />
          )}
        />
      </Drawer>
    );
  }
}

StixCoreRelationshipsExports.propTypes = {
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  exportContext: PropTypes.object,
};

export default compose(inject18n)(StixCoreRelationshipsExports);
