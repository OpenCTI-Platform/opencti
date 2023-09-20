import React from 'react';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

const WidgetText = ({ variant, height, parameters = {} }) => {
  const classes = useStyles();
  const renderContent = () => {
    return (
      <MarkdownDisplay
        content={parameters.content}
        remarkGfmPlugin={true}
        commonmark={true}
      />
    );
  };
  return (
    <div
      style={{
        height: height || '100%',
        marginTop: variant === 'inLine' ? -20 : 0,
      }}
    >
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default WidgetText;
