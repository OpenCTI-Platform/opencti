import React from 'react';
import * as PropTypes from 'prop-types';
import Slide from '@mui/material/Slide';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipsExportsContent, { stixCoreRelationshipsExportsContentQuery } from './StixCoreRelationshipsExportsContent';
import { useFormatter } from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const StixCoreRelationshipsExports = (props) => {
  const { t_i18n } = useFormatter();
  const { paginationOptions, open, handleToggle, exportContext } = props;
  return (
    <Drawer
      open={open}
      onClose={handleToggle}
      title={t_i18n('Exports list')}
      size="medium"
    >
      <QueryRenderer
        query={stixCoreRelationshipsExportsContentQuery}
        variables={{ count: 25, exportContext }}
        render={({ props }) => (
          <StixCoreRelationshipsExportsContent
            handleToggle={handleToggle}
            data={props}
            paginationOptions={paginationOptions}
            exportContext={exportContext}
            isOpen={open}
          />
        )}
      />
    </Drawer>
  );
};

StixCoreRelationshipsExports.propTypes = {
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  exportContext: PropTypes.object,
};

export default StixCoreRelationshipsExports;
