import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import parse from 'html-react-parser';
import Typography from '@material-ui/core/Typography';
import * as R from 'ramda';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  toolbar: {
    margin: '-25px -24px 20px -24px',
    padding: '24px',
    height: '64px',
    backgroundColor: '#1F2842',
  },
  title: {
    float: 'left',
    color: 'white',
  },
});

class HowTo extends Component {
  constructor(props) {
    super(props);
    this.state = {
      htmlFormatData: '',
    };
  }

  componentDidMount() {
    fetch('/static/docs/faq/index.html')
      .then((response) => response.text())
      .then((data) => this.setState({ htmlFormatData: data }));
  }

  render() {
    const {
      location,
      classes,
    } = this.props;
    return (
      <>
        <div
          className={classes.toolbar}
        >
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            About
          </Typography>
        </div>
        <div>
          {parse(this.state.htmlFormatData)}
        </div>
      </>
    );
  }
}

HowTo.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter, withStyles(styles))(HowTo);
