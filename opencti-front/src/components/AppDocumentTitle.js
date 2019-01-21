import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import ReactDocumentTitle from 'react-document-title';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { pathOr } from 'ramda';

class AppDocumentTitle extends Component {
  render() {
    const { children } = this.props;
    const platformTitle = pathOr(null, ['settings', 'platform_title'], this.props);
    const title = platformTitle !== null ? `OpenCTI - ${this.props.settings.platform_title}` : 'OpenCTI - Cyber threat intelligence platform';
    return <ReactDocumentTitle title={title}>{children}</ReactDocumentTitle>;
  }
}
AppDocumentTitle.propTypes = {
  children: PropTypes.node,
  settings: PropTypes.object,
};

export const ConnectedDocumentTitle = createFragmentContainer(AppDocumentTitle, {
  settings: graphql`
      fragment AppDocumentTitle_settings on Settings {
          platform_title
      }
  `,
});

export default AppDocumentTitle;
