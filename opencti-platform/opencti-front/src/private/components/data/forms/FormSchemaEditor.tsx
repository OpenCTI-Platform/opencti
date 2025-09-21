import React, { FunctionComponent } from 'react';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    marginTop: 20,
  },
  editor: {
    '& .MuiInputBase-root': {
      fontFamily: 'monospace',
      fontSize: 13,
    },
  },
  helperText: {
    marginTop: 10,
    fontSize: 12,
  },
  error: {
    color: theme.palette.error.main,
    marginTop: 5,
    fontSize: 12,
  },
}));

interface FormSchemaEditorProps {
  value: string;
  onChange: (value: string) => void;
  error?: string | null;
  helperText?: string;
}

const FormSchemaEditor: FunctionComponent<FormSchemaEditorProps> = ({
  value,
  onChange,
  error,
  helperText,
}) => {
  const classes = useStyles();

  return (
    <div className={classes.container}>
      <Typography variant="body2" color="textSecondary" className={classes.helperText}>
        {helperText}
      </Typography>
      <TextField
        variant="outlined"
        fullWidth
        multiline
        rows={15}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={classes.editor}
        error={!!error}
        placeholder={JSON.stringify({
          version: '1.0',
          mainEntityType: 'Report',
          fields: [
            {
              id: 'name',
              name: 'Name',
              type: 'text',
              required: true,
              stixPath: 'name',
            },
          ],
        }, null, 2)}
      />
      {error && (
        <Typography className={classes.error}>
          {error}
        </Typography>
      )}
      <Typography variant="caption" color="textSecondary" style={{ marginTop: 10, display: 'block' }}>
        Available field types: text, textarea, select, multiselect, checkbox, date, datetime, entity-lookup
      </Typography>
    </div>
  );
};

export default FormSchemaEditor;
