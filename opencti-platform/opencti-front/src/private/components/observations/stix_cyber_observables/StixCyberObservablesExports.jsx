import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Slide from '@mui/material/Slide';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservablesExportsContent, { stixCyberObservablesExportsContentQuery } from './StixCyberObservablesExportsContent';
import Drawer from '@components/common/drawer/Drawer';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class StixCyberObservablesExports extends Component {
  render() {
    const { paginationOptions, open, handleToggle, exportContext, t } = this.props;
    return (
      <Drawer
        open={open}
        elevation={1}
        onClose={handleToggle.bind(this)}
        title={t('Exports list')}
        size="medium"
      >
        <QueryRenderer
          query={stixCyberObservablesExportsContentQuery}
          variables={{ count: 25, exportContext }}
          render={({ props }) => (
            <StixCyberObservablesExportsContent
              handleToggle={handleToggle.bind(this)}
              data={props}
              paginationOptions={paginationOptions}
              isOpen={open}
              exportContext={exportContext}
            />
          )}
        />
      </Drawer>
    );
  }
}

StixCyberObservablesExports.propTypes = {
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  exportContext: PropTypes.object,
};

export default inject18n(StixCyberObservablesExports);
