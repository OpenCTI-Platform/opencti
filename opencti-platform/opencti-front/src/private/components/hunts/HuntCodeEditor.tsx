import React, { KeyboardEvent, ReactNode, UIEvent, useId, useMemo, useRef } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { a11yDark, coy } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';

const FONT_FAMILY = 'Consolas, monaco, monospace';
const FONT_SIZE = 13;
const LINE_HEIGHT = 20;
const PADDING_Y = 8;
const PADDING_X = 12;
const INDENT = '  ';
const VISUALLY_HIDDEN: React.CSSProperties = { position: 'absolute', width: 1, height: 1, margin: -1, padding: 0, overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', border: 0 };

/** Prism grammar used to highlight a hunt query language. */
export const prismLanguageOf = (language?: string | null) => {
  switch ((language ?? '').toLowerCase()) {
    case 'sigma':
    case 'yaml':
      return 'yaml';
    case 'spl':
      return 'splunk-spl';
    case 'kql':
      return 'kusto';
    case 'esql':
    case 'eql':
    case 'ppl':
    case 'sql':
      return 'sql';
    case 'json':
      return 'json';
    default:
      return 'text';
  }
};

/**
 * Inserts the indent at the caret, or indents / outdents every selected line.
 * Returns the new value and selection, pure so it can be unit tested.
 */
export const applyIndent = (value: string, selectionStart: number, selectionEnd: number, outdent: boolean) => {
  const lineStart = value.lastIndexOf('\n', selectionStart - 1) + 1;
  if (!outdent && selectionStart === selectionEnd) {
    return {
      value: value.substring(0, selectionStart) + INDENT + value.substring(selectionEnd),
      selectionStart: selectionStart + INDENT.length,
      selectionEnd: selectionStart + INDENT.length,
    };
  }
  const block = value.substring(lineStart, selectionEnd);
  const lines = block.split('\n');
  let firstLineDelta = 0;
  let totalDelta = 0;
  const changed = lines.map((line, index) => {
    if (outdent) {
      const removed = line.startsWith(INDENT) ? INDENT.length : line.length - line.trimStart().length;
      const delta = Math.min(removed, INDENT.length);
      if (index === 0) firstLineDelta = -delta;
      totalDelta -= delta;
      return line.substring(delta);
    }
    if (index === 0) firstLineDelta = INDENT.length;
    totalDelta += INDENT.length;
    return INDENT + line;
  });
  return {
    value: value.substring(0, lineStart) + changed.join('\n') + value.substring(selectionEnd),
    selectionStart: Math.max(lineStart, selectionStart + firstLineDelta),
    selectionEnd: selectionEnd + totalDelta,
  };
};

interface HuntCodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  label: string;
  language?: string | null;
  minRows?: number;
  maxRows?: number;
  placeholder?: string;
  disabled?: boolean;
  required?: boolean;
  error?: string | null;
  helperText?: string | null;
  /** The secondary action of the field, at the end of its label row */
  labelAction?: ReactNode;
  /** The label row is left out where a heading already names the field; the label still names the input */
  hideLabel?: boolean;
  name?: string;
  testId?: string;
}

/**
 * Code input with syntax highlighting: a transparent native textarea laid over the Prism rendering
 * of the same text (the highlighter already used by CodeBlock), so typing, selection, undo and
 * screen readers keep the native behaviour. Tab indents; Escape then Tab moves the focus out.
 */
export const HuntCodeEditor = ({
  value,
  onChange,
  onBlur,
  label,
  language,
  minRows = 8,
  maxRows = 30,
  placeholder,
  disabled = false,
  required = false,
  error,
  helperText,
  labelAction,
  hideLabel = false,
  name,
  testId,
}: HuntCodeEditorProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const inputId = useId();
  const hintId = useId();
  const keyboardHintId = useId();
  const keyboardHint = t_i18n('Tab indents the selection, press Escape then Tab to leave the editor');
  const hint = error ?? helperText;
  const highlightRef = useRef<HTMLDivElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const releaseFocus = useRef(false);
  const lineCount = Math.max(1, value.split('\n').length);
  const visibleRows = Math.min(maxRows, Math.max(minRows, lineCount));
  const height = visibleRows * LINE_HEIGHT + 2 * PADDING_Y;
  const isDark = theme.palette.mode === 'dark';
  const borderColor = error ? theme.palette.error.main : theme.palette.divider;
  const lineNumbers = useMemo(() => Array.from({ length: lineCount }, (_, index) => index + 1), [lineCount]);

  const sharedTextStyle: React.CSSProperties = {
    fontFamily: FONT_FAMILY,
    fontSize: FONT_SIZE,
    lineHeight: `${LINE_HEIGHT}px`,
    tabSize: 2,
    whiteSpace: 'pre',
    wordWrap: 'normal',
    letterSpacing: 'normal',
  };

  const syncScroll = (event: UIEvent<HTMLTextAreaElement>) => {
    const { scrollTop, scrollLeft } = event.currentTarget;
    if (highlightRef.current) {
      highlightRef.current.scrollTop = scrollTop;
      highlightRef.current.scrollLeft = scrollLeft;
    }
    if (gutterRef.current) {
      gutterRef.current.scrollTop = scrollTop;
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Escape') {
      releaseFocus.current = true;
      return;
    }
    if (event.key === 'Tab' && !releaseFocus.current) {
      event.preventDefault();
      const target = event.currentTarget;
      const next = applyIndent(target.value, target.selectionStart, target.selectionEnd, event.shiftKey);
      onChange(next.value);
      requestAnimationFrame(() => {
        target.selectionStart = next.selectionStart;
        target.selectionEnd = next.selectionEnd;
      });
      return;
    }
    releaseFocus.current = false;
  };

  return (
    <div data-testid={testId}>
      {!hideLabel && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1), minHeight: 28, marginBottom: theme.spacing(0.5) }}>
          <Text
            as="label"
            htmlFor={inputId}
            variant="content-compact"
            style={{ color: error ? theme.palette.error.main : theme.palette.text.secondary }}
          >
            {label}{required ? ' *' : ''}
          </Text>
          {labelAction}
        </div>
      )}
      <div
        style={{
          display: 'flex',
          height,
          border: `1px solid ${borderColor}`,
          borderRadius: theme.borderRadius,
          overflow: 'hidden',
          background: theme.palette.background.default,
          opacity: disabled ? 0.6 : 1,
        }}
      >
        <div
          ref={gutterRef}
          aria-hidden
          style={{
            ...sharedTextStyle,
            padding: `${PADDING_Y}px 8px`,
            textAlign: 'right',
            color: theme.palette.text.secondary,
            userSelect: 'none',
            overflow: 'hidden',
            borderRight: `1px solid ${theme.palette.divider}`,
            minWidth: 40,
          }}
        >
          {lineNumbers.map((lineNumber) => <div key={lineNumber}>{lineNumber}</div>)}
        </div>
        <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
          <div
            ref={highlightRef}
            aria-hidden
            style={{ position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none' }}
          >
            {value.length === 0 && placeholder ? (
              // The textarea text is transparent, so its native placeholder is drawn here instead
              <div
                data-testid={testId ? `${testId}-placeholder` : undefined}
                style={{ ...sharedTextStyle, padding: `${PADDING_Y}px ${PADDING_X}px`, color: theme.palette.text.disabled }}
              >
                {placeholder}
              </div>
            ) : (
              <SyntaxHighlighter
                language={prismLanguageOf(language)}
                style={isDark ? a11yDark : coy}
                customStyle={{
                  ...sharedTextStyle,
                  margin: 0,
                  padding: `${PADDING_Y}px ${PADDING_X}px`,
                  background: 'transparent',
                  overflow: 'visible',
                  minHeight: '100%',
                  border: 'none',
                  boxShadow: 'none',
                }}
                codeTagProps={{ style: { ...sharedTextStyle, background: 'transparent' } }}
              >
                {/* A trailing newline keeps the last line of the overlay aligned with the textarea */}
                {`${value}\n`}
              </SyntaxHighlighter>
            )}
          </div>
          <textarea
            id={inputId}
            aria-label={hideLabel ? label : undefined}
            name={name}
            value={value}
            placeholder={placeholder}
            disabled={disabled}
            required={required}
            aria-invalid={!!error}
            aria-describedby={hint ? `${hintId} ${keyboardHintId}` : hintId}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
            onChange={(event) => onChange(event.target.value)}
            onBlur={onBlur}
            onScroll={syncScroll}
            onKeyDown={onKeyDown}
            style={{
              ...sharedTextStyle,
              position: 'absolute',
              inset: 0,
              width: '100%',
              height: '100%',
              margin: 0,
              padding: `${PADDING_Y}px ${PADDING_X}px`,
              border: 'none',
              outline: 'none',
              resize: 'none',
              overflow: 'auto',
              background: 'transparent',
              color: 'transparent',
              WebkitTextFillColor: 'transparent',
              caretColor: theme.palette.text.primary,
            }}
          />
        </div>
      </div>
      <Text
        id={hintId}
        variant="content-caption"
        style={{ display: 'block', marginTop: theme.spacing(0.5), color: error ? theme.palette.error.main : theme.palette.text.secondary }}
      >
        {hint ?? keyboardHint}
      </Text>
      {hint && <span id={keyboardHintId} style={VISUALLY_HIDDEN}>{keyboardHint}</span>}
    </div>
  );
};

type HuntCodeEditorFieldProps = FieldProps<string> & Omit<HuntCodeEditorProps, 'value' | 'onChange' | 'error' | 'name'> & {
  onValueChange?: (value: string) => void;
};

/** Formik binding of the code editor. */
export const HuntCodeEditorField = ({ field, form, onValueChange, ...props }: HuntCodeEditorFieldProps) => {
  const [, meta] = useField(field.name);
  const showError = !!meta.error && (meta.touched || form.submitCount > 0);
  return (
    <HuntCodeEditor
      {...props}
      name={field.name}
      value={field.value ?? ''}
      error={showError ? String(meta.error) : null}
      onChange={(next) => {
        form.setFieldValue(field.name, next);
        onValueChange?.(next);
      }}
      onBlur={() => form.setFieldTouched(field.name, true)}
    />
  );
};

export default HuntCodeEditor;
