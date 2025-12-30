const chalk = require('chalk');

const LEVEL_COLORS = {
  error: chalk.red.bold,
  warn: chalk.yellow,
  info: chalk.blue,
  debug: chalk.gray,
};

const CATEGORY_COLORS = {
  APP: chalk.cyan,
  AUDIT: chalk.magenta,
  TECHNICAL: chalk.green,
  MIGRATION: chalk.yellowBright,
  SUPPORT: chalk.blueBright,
  TELEMETRY: chalk.grayBright,
  UNKNOWN: chalk.violet,
};

// Format a timestamp to HH:MM:SS
function formatTime(timestamp) {
  const date = new Date(timestamp);
  return chalk.gray(date.toLocaleTimeString('en-US', { hour12: false }));
}

function formatLevel(level) {
  const colorFn = LEVEL_COLORS[level] || chalk.white;
  return colorFn(level.toUpperCase().padEnd(5));
}

function formatCategory(category) {
  const colorFn = CATEGORY_COLORS[category] || chalk.white;
  return colorFn(`[${category}]`);
}

function formatExtraFields(log) {
  const standardFields = ['category', 'environment', 'level', 'message', 'source', 'timestamp', 'version'];
  const extraFields = Object.keys(log).filter(key => !standardFields.includes(key));
  
  if (extraFields.length === 0) {
    return '';
  }
  
  const extras = extraFields.map(key => {
    return chalk.dim(`${key}: ${JSON.stringify(log[key], null, 2)}`);
  }).join('\n');
  
  return `\n${extras}`;
}

/**
 * Try to parse a line as JSON and format it nicely
 * Returns the formatted string or null if not JSON
 */
function tryFormatJsonLog(line) {
  try {
    const log = JSON.parse(line);
    
    // Check if it looks like an OpenCTI log
    if (!log.timestamp || !log.message) {
      return null;
    }
    
    const time = formatTime(log.timestamp);
    const level = formatLevel(log.level || 'info');
    const category = log.category ? formatCategory(log.category) : '     ';
    const message = chalk.white(log.message);
    const extras = formatExtraFields(log);
    
    return `${time} ${level} ${category} ${message}${extras}`;
  } catch {
    return null;
  }
}

/**
 * Format a log line, either JSON or plain text
 */
function formatLogLine(line) {
  // Try to format as JSON first
  const formattedJson = tryFormatJsonLog(line);
  if (formattedJson) {
    return formattedJson;
  }
  
  // Not JSON, return with basic formatting, we can add new patterns if needed
  if (line.includes('DeprecationWarning')) {
    return chalk.yellow(line);
  }
  if (line.includes('Error') || line.includes('ERROR')) {
    return chalk.red(line);
  }
  if (line.includes('Warning') || line.includes('WARN')) {
    return chalk.yellow(line);
  }

  return line;
}

function formatOutput(data) {
  const text = data.toString();
  const lines = text.split('\n');

  return lines
    .filter(line => line.trim().length > 0)
    .map(line => formatLogLine(line))
    .join('\n');
}

module.exports = {
  formatOutput,
  formatLogLine,
};
