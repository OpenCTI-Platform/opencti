import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Chip from '@mui/material/Chip';
import Button from '@mui/material/Button';
import DialogActions from '@mui/material/DialogActions';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { CheckCircleOutlined, ErrorOutlined, InfoOutlined, WarningAmberOutlined, ContentCopyOutlined, OpenInNewOutlined } from '@mui/icons-material';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { a11yDark, coy } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { Theme } from '../../../../components/Theme';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import ButtonCommon from '@common/button/Button';
const formatTimestamp = (ts: string | unknown): string => {
  if (!ts) return '—';
  const d = new Date(ts as string);
  if (Number.isNaN(d.getTime())) return '—';
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${ms}`;
};

export interface AuthLogEntryShape {
  readonly timestamp: unknown;
  readonly level: string;
  readonly message: string;
  readonly type: string;
  readonly identifier: string;
  readonly meta?: unknown;
}

interface AuthProviderLogTabProps {
  authLogHistory: ReadonlyArray<AuthLogEntryShape>;
}

const levelColor = (level: string) => {
  switch (level) {
    case 'error':
      return 'error';
    case 'warn':
      return 'warning';
    case 'success':
      return 'success';
    default:
      return 'default';
  }
};

const LevelIcon = ({ level }: { level: string }) => {
  switch (level) {
    case 'error':
      return <ErrorOutlined fontSize="small" color="error" />;
    case 'warn':
      return <WarningAmberOutlined fontSize="small" sx={{ color: 'warning.main' }} />;
    case 'success':
      return <CheckCircleOutlined fontSize="small" color="success" />;
    default:
      return <InfoOutlined fontSize="small" color="action" />;
  }
};

const TIMESTAMP_WIDTH = '11.5rem';
const LEVEL_WIDTH = '8rem';
const DETAILS_PREVIEW_MAX_LEN = 56;

type JsonTokenType = 'punctuation' | 'key' | 'string' | 'number' | 'keyword';
type Segment = { type: JsonTokenType; value: string };

const serializeToColoredSegments = (value: unknown, maxChars: number): { segments: Segment[]; truncated: boolean } => {
  const segments: Segment[] = [];
  let len = 0;
  let truncated = false;

  const add = (type: JsonTokenType, raw: string): void => {
    truncated ||= (len + raw.length) > maxChars;
    const take = Math.min(raw.length, maxChars - len);
    if (take > 0) {
      segments.push({ type, value: raw.slice(0, take) });
      len += take;
    }
  };

  const serialize = (val: unknown): void => {
    if (val === null) {
      add('keyword', 'null');
    } else if (typeof val === 'boolean') {
      add('keyword', val ? 'true' : 'false');
    } else if (typeof val === 'number') {
      add('number', Number.isFinite(val) ? String(val) : 'null');
    } else if (Array.isArray(val)) {
      add('punctuation', '[');
      for (let i = 0; i < val.length && len < maxChars; i++) {
        if (i > 0) add('punctuation', ',');
        serialize(val[i]);
      }
      if (len < maxChars) add('punctuation', ']');
    } else if (typeof val === 'object') {
      add('punctuation', '{');
      const entries = Object.entries(val);
      for (let i = 0; i < entries.length && len < maxChars; i++) {
        if (i > 0) add('punctuation', ',');
        const [k, v] = entries[i];
        add('key', JSON.stringify(k));
        add('punctuation', ':');
        serialize(v);
      }
      if (len < maxChars) add('punctuation', '}');
    } else {
      add('string', JSON.stringify(String(val)));
    }
  };
  serialize(value);

  return { segments, truncated };
};

// Align preview colors with Prism themes used in the details panel (a11yDark / coy)
const jsonTokenColor = (type: JsonTokenType, theme: Theme): string => {
  const isDark = theme.palette.mode === 'dark';
  switch (type) {
    case 'punctuation':
      return isDark ? '#fefefe' : '#5F6364'; // a11yDark / coy
    case 'key':
      return isDark ? '#ffa07a' : '#c92c2c'; // property
    case 'string':
      return isDark ? '#abe338' : '#2f9c0a'; // string
    case 'number':
      return isDark ? '#00e0e0' : '#c92c2c'; // number
    case 'keyword':
      return isDark ? '#00e0e0' : '#1990b8'; // boolean, keyword (true/false/null)
    default:
      return theme.palette.text?.primary ?? '#000';
  }
};

const AuthProviderLogTab: React.FC<AuthProviderLogTabProps> = ({ authLogHistory }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [detailsOpen, setDetailsOpen] = useState<{ index: number; entry: AuthLogEntryShape } | null>(null);

  const handleCopyDetails = () => {
    if (!detailsOpen?.entry.meta) return;
    const text = JSON.stringify(detailsOpen.entry.meta, null, 2);
    navigator.clipboard.writeText(text);
  };

  if (!authLogHistory || authLogHistory.length === 0) {
    return (
      <Box sx={{ py: 2, color: 'text.secondary' }}>
        No log entries yet. Logs appear here when authentication attempts or provider actions occur.
      </Box>
    );
  }

  return (
    <>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          flex: 1,
          minHeight: 0,
          overflow: 'hidden',
        }}
      >
        <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
          <Table size="small" stickyHeader sx={{ tableLayout: 'fixed', width: '100%' }}>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 600, width: TIMESTAMP_WIDTH, minWidth: TIMESTAMP_WIDTH, backgroundColor: 'background.paper', zIndex: 1 }}>Timestamp</TableCell>
                <TableCell sx={{ fontWeight: 600, width: LEVEL_WIDTH, minWidth: LEVEL_WIDTH, backgroundColor: 'background.paper', zIndex: 1 }}>Level</TableCell>
                <TableCell sx={{ fontWeight: 600, width: '22%', backgroundColor: 'background.paper', zIndex: 1 }}>Message</TableCell>
                <TableCell sx={{ fontWeight: 600, backgroundColor: 'background.paper', zIndex: 1 }}>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {authLogHistory.map((entry, index) => (
                <TableRow key={`${entry.timestamp}-${index}`} hover>
                  <TableCell sx={{ whiteSpace: 'nowrap', width: TIMESTAMP_WIDTH, minWidth: TIMESTAMP_WIDTH, fontFamily: 'monospace', fontSize: '0.8125rem' }}>
                    {formatTimestamp(entry.timestamp)}
                  </TableCell>
                  <TableCell sx={{ width: LEVEL_WIDTH, minWidth: LEVEL_WIDTH, overflow: 'visible', whiteSpace: 'nowrap' }}>
                    <Chip
                      size="small"
                      icon={<LevelIcon level={entry.level} />}
                      label={entry.level}
                      color={levelColor(entry.level) as 'error' | 'warning' | 'success' | 'default'}
                      variant="outlined"
                      sx={{
                        paddingTop: 0.75,
                        paddingBottom: 0.75,
                        paddingLeft: 0.75,
                        paddingRight: 0.75,
                        '& .MuiChip-icon': { marginLeft: 0, marginRight: 0.5 },
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ maxWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.message}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 0 }}>
                    {entry.meta && Object.keys(entry.meta).length > 0 ? (
                      <Box
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 0.25,
                          minWidth: 0,
                        }}
                      >
                        <Box
                          component="span"
                          onClick={() => setDetailsOpen({ index, entry })}
                          sx={{
                            flex: 1,
                            minWidth: 0,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontSize: '0.75rem',
                            fontFamily: 'monospace',
                            cursor: 'pointer',
                          }}
                          title={(() => {
                            try {
                              const raw = JSON.stringify(entry.meta);
                              return raw.length > DETAILS_PREVIEW_MAX_LEN ? `${raw.slice(0, DETAILS_PREVIEW_MAX_LEN)}…` : raw;
                            } catch {
                              return '—';
                            }
                          })()}
                        >
                          {(() => {
                            const { segments, truncated } = serializeToColoredSegments(entry.meta, DETAILS_PREVIEW_MAX_LEN);
                            if (segments.length === 0) return '—';
                            return (
                              <>
                                {segments.map((seg, i) => (
                                  <Box
                                    key={i}
                                    component="span"
                                    sx={{ color: jsonTokenColor(seg.type, theme) }}
                                  >
                                    {seg.value}
                                  </Box>
                                ))}
                                {truncated && (
                                  <Box component="span" sx={{ color: 'text.secondary' }}>
                                    …
                                  </Box>
                                )}
                              </>
                            );
                          })()}
                        </Box>
                        <Tooltip title={t_i18n('View full details')}>
                          <IconButton
                            size="small"
                            onClick={() => setDetailsOpen({ index, entry })}
                            sx={{ flexShrink: 0, padding: 0.25 }}
                            aria-label={t_i18n('View full details')}
                          >
                            <OpenInNewOutlined sx={{ fontSize: '1rem' }} />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    ) : (
                      '—'
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
      </Box>

      <Dialog
        open={detailsOpen !== null}
        onClose={() => setDetailsOpen(null)}
        title={t_i18n('Log details')}
        size="large"
        showCloseButton
      >
        {detailsOpen !== null && detailsOpen.entry.meta != null && (
          <>
            <Box sx={{ borderRadius: 1, overflow: 'hidden', '& pre': { margin: 0 } }}>
              <SyntaxHighlighter
                language="json"
                style={theme.palette.mode === 'dark' ? a11yDark : coy}
                customStyle={{
                  margin: 0,
                  padding: 16,
                  fontSize: '0.8125rem',
                  maxHeight: '70vh',
                  borderRadius: 4,
                }}
                showLineNumbers={false}
              >
                {JSON.stringify(detailsOpen.entry.meta, null, 2)}
              </SyntaxHighlighter>
            </Box>
            <DialogActions sx={{ px: 0, pt: 2 }}>
              <Button
                size="small"
                startIcon={<ContentCopyOutlined />}
                onClick={handleCopyDetails}
              >
                {t_i18n('Copy')}
              </Button>
              <ButtonCommon onClick={() => setDetailsOpen(null)}>
                {t_i18n('Close')}
              </ButtonCommon>
            </DialogActions>
          </>
        )}
      </Dialog>
    </>
  );
};

export default AuthProviderLogTab;
