import { useSettingsMessagesBannerHeight } from './SettingsMessagesBanner';

const withHooksSettingsMessagesBannerHeight = (Component) => {
  return (props) => {
    const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

    return <Component settingsMessagesBannerHeight={settingsMessagesBannerHeight} {...props} />;
  };
};

export default withHooksSettingsMessagesBannerHeight;
