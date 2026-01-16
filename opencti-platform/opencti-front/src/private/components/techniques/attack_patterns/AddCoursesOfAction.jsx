import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddCoursesOfActionLines, { addCoursesOfActionLinesQuery } from './AddCoursesOfActionLines';
import CourseOfActionCreation from '../courses_of_action/CourseOfActionCreation';

class AddCoursesOfAction extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const { t, attackPattern, attackPatternCoursesOfAction } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Add courses of action')}
          header={(
            <>
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
              />
              <CourseOfActionCreation
                display={this.state.open}
                contextual={true}
                inputValue={this.state.search}
                paginationOptions={paginationOptions}
              />
            </>
          )}
        >
          <QueryRenderer
            query={addCoursesOfActionLinesQuery}
            variables={{
              search: this.state.search,
              count: 20,
            }}
            render={({ props }) => {
              return (
                <AddCoursesOfActionLines
                  attackPattern={attackPattern}
                  attackPatternCoursesOfAction={attackPatternCoursesOfAction}
                  data={props}
                />
              );
            }}
          />
        </Drawer>
      </>
    );
  }
}

AddCoursesOfAction.propTypes = {
  attackPattern: PropTypes.object,
  attackPatternCoursesOfAction: PropTypes.array,
  t: PropTypes.func,
};

export default compose(inject18n)(AddCoursesOfAction);
