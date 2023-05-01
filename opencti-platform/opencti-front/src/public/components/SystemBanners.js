import React from 'react';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../components/i18n';
import { SYSTEM_BANNER_HEIGHT, getBannerSettings, bannerColorClassName } from '../../utils/SystemBanners';
import { commitLocalUpdate } from '../../relay/environment';

const BANNER_Z_INDEX = 2000;

const styles = () => ({
  banner: {
    textAlign: 'center',
    height: `${SYSTEM_BANNER_HEIGHT}px`,
    width: '100%',
    position: 'fixed',
    zIndex: BANNER_Z_INDEX,
  },
  bannerTop: {
    top: 0,
  },
  bannerBottom: {
    bottom: 0,
  },
  bannerGreen: {
    background: '#00840C',
  },
  bannerRed: {
    background: '#ef0000',
  },
  bannerYellow: {
    background: '#ffff00',
  },
  classificationText: {
    height: `${SYSTEM_BANNER_HEIGHT - 4}px`,
    fontFamily: 'Arial,Helvetica,Geneva,Swiss,sans-serif',
    fontWeight: 'bold',
    padding: '2px 0',
    position: 'relative',
  },
  classificationTextGreen: {
    color: '#ffff00',
  },
  classificationTextRed: {
    color: '#ffffff',
  },
  classificationTextYellow: {
    color: '#000000',
  },
});

class SystemBanners extends React.Component {
  constructor(props) {
    super(props);
    this.handleLogout = props.handleLogout;
    commitLocalUpdate((store) => {
      // Handles NoAuth error when not logged in
      if (store.getRoot().getLinkedRecord('me')) {
        const me = store.getRoot().getLinkedRecord('me');
        this.accountStatus = me.getValue('account_status');
      }
    });
    this.state = {
      bannerMessage: '',
      bannerLevel: '',
    };
    // These local versions of the state variables are necessary to control state updates
    this.bannerLevel = '';
    this.bannerMessage = '';
  }

  updateBanners = (bannerSettings) => {
    const { bannerLevel, bannerText: bannerMessage, bannerHeight } = bannerSettings;
    this.bannerLevel = bannerLevel;
    this.bannerMessage = bannerMessage;
    this.setState({ bannerLevel, bannerMessage });
    if (R.is(Function, this.props.handleBannerChange)) {
      this.props.handleBannerChange(bannerHeight);
    }
  };

  componentDidMount() {
    getBannerSettings(this.updateBanners);
  }

  componentDidUpdate() {
    getBannerSettings((settings) => {
      const { bannerLevel, bannerText } = settings;
      if (this.bannerLevel !== bannerLevel || this.bannerMessage !== bannerText) {
        this.updateBanners(settings);
      }
    });
  }

  checkAccountStatus(accountStatus) {
    if (accountStatus === 'Inactive') {
      const getUrl = window.location;
      // var baseUrl = getUrl.protocol + "//" + getUrl.host + "/" + getUrl.pathname.split('/')[1];
      // Redirect to the Dashboard Homepage flagging your account Inactive
      this.handleLogout(`${getUrl.protocol}//${getUrl.host}/dashboard?AccountInactive=1`);
    } else if (accountStatus === 'Locked') {
      const getUrl = window.location;
      // var baseUrl = getUrl.protocol + "//" + getUrl.host + "/" + getUrl.pathname.split('/')[1];
      // Redirect to the Dashboard Homepage flagging your account Locked
      this.handleLogout(`${getUrl.protocol}//${getUrl.host}/dashboard?AccountLocked=1`);
    } else if (accountStatus === 'LockedTraining') {
      const getUrl = window.location;
      // var baseUrl = getUrl.protocol + "//" + getUrl.host + "/" + getUrl.pathname.split('/')[1];
      // Redirect to the Dashboard Homepage flagging your account Locked
      this.handleLogout(`${getUrl.protocol}//${getUrl.host}/dashboard?AccountLocked=2`);
    } else if (accountStatus === 'Active') {
      // Do nothing
    }
  }

  render() {
    // Check Account Status
    this.checkAccountStatus(this.accountStatus);

    const { classes } = this.props;
    const { bannerMessage, bannerLevel } = this.state;

    const bannerColor = bannerColorClassName(bannerLevel);
    const bannerTextColor = bannerColorClassName(bannerLevel, 'classificationText');

    const topBannerClasses = [
      classes.banner, classes.bannerTop, classes[bannerColor],
    ].join(' ');
    const bottomBannerClasses = [
      classes.banner, classes.bannerBottom, classes[bannerColor],
    ].join(' ');
    const bannerTextClasses = [
      classes.classificationText, classes[bannerTextColor],
    ].join(' ');

    return bannerLevel && (
      <div>
        <div className={topBannerClasses}>
          <span className={bannerTextClasses}>
            {bannerMessage}
          </span>
        </div>
        <div className={bottomBannerClasses}>
          <span className={bannerTextClasses}>
            {bannerMessage}
          </span>
        </div>
      </div>
    );
  }
}

export default R.compose(inject18n, withStyles(styles))(SystemBanners);
