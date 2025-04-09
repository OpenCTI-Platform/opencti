import React from 'react';
import { useSettingsMessagesBannerHeight } from './SettingsMessagesBanner';

const withHooksSettingsMessagesBannerHeight = (Component) => {
  const ComponentWithSettingsMessagesBannerHeight = (props) => {
    const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
    return <Component settingsMessagesBannerHeight={settingsMessagesBannerHeight} {...props} />;
  };

  ComponentWithSettingsMessagesBannerHeight.displayName = `${Component.displayName ?? 'Component'}_withHooksSettingsMessagesBannerHeight`;

  return ComponentWithSettingsMessagesBannerHeight;
};

export default withHooksSettingsMessagesBannerHeight;
