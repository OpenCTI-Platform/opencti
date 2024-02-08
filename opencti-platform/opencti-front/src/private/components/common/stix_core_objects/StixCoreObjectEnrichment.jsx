import React, { Component } from 'react';
import * as R from 'ramda';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCoreObjectEnrichmentLines, { stixCoreObjectEnrichmentLinesQuery } from './StixCoreObjectEnrichmentLines';

class StixCoreObjectEnrichment extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    if (this.props.closeMenu) {
      this.props.closeMenu();
    }
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  render() {
    const { t, stixCoreObjectId, handleClose, open } = this.props;
    return (
      <>
        {!handleClose
          && <Tooltip title={t('Enrichment')}>
            <ToggleButton
              onClick={this.handleOpen.bind(this)}
              value="enrich"
              size="small"
              style={{ marginRight: 3 }}
            >
              <CloudRefreshOutline fontSize="small" color="primary" />
            </ToggleButton>
          </Tooltip>
        }
        <Drawer
          open={open || this.state.open}
          onClose={handleClose || this.handleClose.bind(this)}
          title={t('Enrichment connectors')}
        >
          <QueryRenderer
            query={stixCoreObjectEnrichmentLinesQuery}
            variables={{ id: stixCoreObjectId }}
            render={({ props: queryProps }) => {
              if (
                queryProps
                && queryProps.stixCoreObject
                && queryProps.connectorsForImport
              ) {
                return (
                  <StixCoreObjectEnrichmentLines
                    stixCoreObject={queryProps.stixCoreObject}
                    connectorsForImport={queryProps.connectorsForImport}
                  />
                );
              }
              return <div />;
            }}
          />
        </Drawer>
      </>
    );
  }
}

export default R.compose(inject18n)(StixCoreObjectEnrichment);
