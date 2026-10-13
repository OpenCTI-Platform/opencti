import Dialog from '@common/dialog/Dialog';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { CSSProperties, FunctionComponent, useEffect, useRef, useState } from 'react';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

const MAX_LENGTH = 30;

interface TruncatedRawValueProps {
  value: string;
  variant?: 'code' | 'text';
  style?: CSSProperties;
}

const TruncatedRawValue: FunctionComponent<TruncatedRawValueProps> = ({ value, variant = 'code', style }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const theme = useTheme<Theme>();
  const textRef = useRef<HTMLElement>(null);
  const [isOverflowing, setIsOverflowing] = useState(false);

  useEffect(() => {
    if (variant === 'text' && textRef.current) {
      setIsOverflowing(textRef.current.scrollWidth > textRef.current.clientWidth);
    }
  }, [value, variant]);

  if (!value) {
    return variant === 'code' ? <pre style={{ margin: 0 }}>-</pre> : <>-</>;
  }

  const dialog = (
    <Dialog
      open={open}
      onClose={() => setOpen(false)}
      fullWidth
      title={t_i18n('Raw value')}
    >
      {variant === 'code'
        ? <pre>{value}</pre>
        : <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{value}</span>
      }
      <DialogActions>
        <Button onClick={() => setOpen(false)}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );

  if (variant === 'text') {
    return (
      <>
        {/* describeChild: the full value stays the button's name, the tooltip only describes it */}
        <Tooltip title={isOverflowing ? t_i18n('Click to view full value') : ''} describeChild>
          {/* FDS-WORKAROUND #67: bare <button>, the library Button and IconButton always paint a box — see fds-migration/LIBRARY-FEEDBACK.md #67 */}
          <Box
            ref={textRef}
            // One element measures and shows the value: a button only once it is truncated
            component={isOverflowing ? 'button' : 'div'}
            type={isOverflowing ? 'button' : undefined}
            onClick={isOverflowing ? () => setOpen(true) : undefined}
            sx={{
              display: 'block',
              width: '100%',
              padding: 0,
              border: 'none',
              background: 'none',
              font: 'inherit',
              lineHeight: 'inherit',
              textAlign: 'left',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              cursor: isOverflowing ? 'pointer' : 'default',
              color: theme.palette.text?.secondary,
              ...style,
            }}
          >
            {value}
          </Box>
        </Tooltip>
        {isOverflowing && dialog}
      </>
    );
  }

  // variant === 'code'
  const codeStyle: CSSProperties = {
    fontFamily: 'Consolas, monaco, monospace',
    margin: 0,
    color: theme.palette.text?.secondary,
    ...style,
  };

  if (value.length <= MAX_LENGTH) {
    return (
      <pre style={codeStyle}>{value}</pre>
    );
  }

  return (
    <>
      <Tooltip title={t_i18n('Click to view full value')} describeChild>
        {/* FDS-WORKAROUND #67: bare <button>, the library Button and IconButton always paint a box — see fds-migration/LIBRARY-FEEDBACK.md #67 */}
        <button
          type="button"
          onClick={() => setOpen(true)}
          style={{
            ...codeStyle,
            border: 'none',
            padding: 0,
            background: 'none',
            textAlign: 'left',
            whiteSpace: 'pre-wrap',
          }}
        >
          {value.substring(0, MAX_LENGTH)}...
        </button>
      </Tooltip>
      {dialog}
    </>
  );
};

export default TruncatedRawValue;
