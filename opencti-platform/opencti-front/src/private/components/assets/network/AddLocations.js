// import React, { Component } from 'react';
// import * as PropTypes from 'prop-types';
// import { compose } from 'ramda';
// import { withStyles } from '@material-ui/core/styles';
// import Drawer from '@material-ui/core/Drawer';
// import IconButton from '@material-ui/core/IconButton';
// import List from '@material-ui/core/List';
// import ListItem from '@material-ui/core/ListItem';
// import ListItemIcon from '@material-ui/core/ListItemIcon';
// import ListItemText from '@material-ui/core/ListItemText';
// import Typography from '@material-ui/core/Typography';
// import { Add, Close } from '@material-ui/icons';
// import Skeleton from '@material-ui/lab/Skeleton';
// import inject18n from '../../../../components/i18n';
// import SearchInput from '../../../../components/SearchInput';
// import { QueryRenderer } from '../../../../relay/environment';
// import AddLocationsLines, { addLocationsLinesQuery } from './AddLocationsLines';
// import LocationCreation from '../../common/location/LocationCreation';

// const styles = (theme) => ({
//   drawerPaper: {
//     minHeight: '100vh',
//     width: '50%',
//     position: 'fixed',
//     backgroundColor: theme.palette.navAlt.background,
//     transition: theme.transitions.create('width', {
//       easing: theme.transitions.easing.sharp,
//       duration: theme.transitions.duration.enteringScreen,
//     }),
//     padding: 0,
//   },
//   createButton: {
//     float: 'left',
//     marginTop: -15,
//   },
//   title: {
//     float: 'left',
//   },
//   search: {
//     float: 'right',
//   },
//   header: {
//     backgroundColor: theme.palette.navAlt.backgroundHeader,
//     color: theme.palette.navAlt.backgroundHeaderText,
//     padding: '20px 20px 20px 60px',
//   },
//   closeButton: {
//     position: 'absolute',
//     top: 12,
//     left: 5,
//     color: 'inherit',
//   },
//   container: {
//     padding: 0,
//   },
//   placeholder: {
//     display: 'inline-block',
//     height: '1em',
//     backgroundColor: theme.palette.grey[700],
//   },
//   avatar: {
//     width: 24,
//     height: 24,
//   },
// });

// class AddLocations extends Component {
//   constructor(props) {
//     super(props);
//     this.state = { open: false, search: '' };
//   }

//   handleOpen() {
//     this.setState({ open: true });
//   }

//   handleClose() {
//     this.setState({ open: false, search: '' });
//   }

//   handleSearch(keyword) {
//     this.setState({ search: keyword });
//   }

//   render() {
//     const {
//       t, classes, networkId, networkLocations,
//     } = this.props;
//     const paginationOptions = {
//       search: this.state.search,
//     };
//     return (
//       <div>
//         <IconButton
//           color="secondary"
//           aria-label="Add"
//           onClick={this.handleOpen.bind(this)}
//           classes={{ root: classes.createButton }}
//         >
//           <Add fontSize="small" />
//         </IconButton>
//         <Drawer
//           open={this.state.open}
//           anchor="right"
//           classes={{ paper: classes.drawerPaper }}
//           onClose={this.handleClose.bind(this)}
//         >
//           <div className={classes.header}>
//             <IconButton
//               aria-label="Close"
//               className={classes.closeButton}
//               onClick={this.handleClose.bind(this)}
//             >
//               <Close fontSize="small" />
//             </IconButton>
//             <Typography variant="h6" classes={{ root: classes.title }}>
//               {t('Add locations')}
//             </Typography>
//             <div className={classes.search}>
//               <SearchInput
//                 variant="inDrawer"
//                 placeholder={`${t('Search')}...`}
//                 onSubmit={this.handleSearch.bind(this)}
//               />
//             </div>
//           </div>
//           <div className={classes.container}>
//             <QueryRenderer
//               query={addLocationsLinesQuery}
//               variables={{
//                 search: this.state.search,
//                 count: 20,
//               }}
//               render={({ props }) => {
//                 if (props) {
//                   return (
//                     <AddLocationsLines
//                       networkId={networkId}
//                       networkLocations={networkLocations}
//                       data={props}
//                     />
//                   );
//                 }
//                 return (
//                   <List>
//                     {Array.from(Array(20), (e, i) => (
//                       <ListItem key={i} divider={true} button={false}>
//                         <ListItemIcon>
//                           <Skeleton
//                             animation="wave"
//                             variant="circle"
//                             width={30}
//                             height={30}
//                           />
//                         </ListItemIcon>
//                         <ListItemText
//                           primary={
//                             <Skeleton
//                               animation="wave"
//                               variant="rect"
//                               width="90%"
//                               height={15}
//                               style={{ marginBottom: 10 }}
//                             />
//                           }
//                           secondary={
//                             <Skeleton
//                               animation="wave"
//                               variant="rect"
//                               width="90%"
//                               height={15}
//                             />
//                           }
//                         />
//                       </ListItem>
//                     ))}
//                   </List>
//                 );
//               }}
//             />
//           </div>
//         </Drawer>
//         <LocationCreation
//           display={this.state.open}
//           contextual={true}
//           inputValue={this.state.search}
//           paginationOptions={paginationOptions}
//         />
//       </div>
//     );
//   }
// }

// AddLocations.propTypes = {
//   networkId: PropTypes.string,
//   networkLocations: PropTypes.array,
//   classes: PropTypes.object,
//   t: PropTypes.func,
// };

// export default compose(inject18n, withStyles(styles))(AddLocations);
