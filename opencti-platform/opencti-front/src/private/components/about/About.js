import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import parse from 'html-react-parser';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import rehypeRaw from 'rehype-raw';
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

class About extends Component {
  constructor(props) {
    super(props);
    this.state = {
      htmlFormatData: '',
    };
  }

  componentDidMount() {
    fetch('/static/docs/about.html')
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
          {/* <Markdown
            remarkPlugins={[remarkGfm, remarkParse]}
            rehypePlugins={[rehypeRaw]}
            parserOptions={{ commonmark: true }}
          > */}
          {parse(this.state.htmlFormatData)}
          {/* {this.state.htmlFormatData} */}
          {/* </Markdown> */}
        </div>
      </>
    );
  }
}

About.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter, withStyles(styles))(About);
