import { GraphQLScalarType, Kind } from 'graphql';

// Check whether a certain year is a leap year.
//
// Every year that is exactly divisible by four
// is a leap year, except for years that are exactly
// divisible by 100, but these centurial years are
// leap years if they are exactly divisible by 400.
// For example, the years 1700, 1800, and 1900 are not leap years,
// but the years 1600 and 2000 are.
//
const leapYear = (year) => {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
};

const validateJSDate = (date) => {
  const time = date.getTime();
    return time === time; // eslint-disable-line
};

const serializeDate = (date) => {
  return date.toISOString().split('T')[0];
};

const validateDate = (datestring) => {
  const RFC_3339_REGEX = /^(\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]))$/;
  if (!RFC_3339_REGEX.test(datestring)) {
    return false;
  }
  // Verify the correct number of days for
  // the month contained in the date-string.
  const year = Number(datestring.substr(0, 4));
  const month = Number(datestring.substr(5, 2));
  const day = Number(datestring.substr(8, 2));
  switch (month) {
    case 2: // February
      if (leapYear(year) && day > 29) {
        return false;
      }
      if (!leapYear(year) && day > 28) {
        return false;
      }
      return true;
    case 4: // April
    case 6: // June
    case 9: // September
    case 11: // November
      if (day > 30) {
        return false;
      }
      break;
  }
  return true;
};

const validateDateTime = (dateTimeString) => {
  dateTimeString = dateTimeString === null || dateTimeString === void 0 ? void 0 : dateTimeString.toUpperCase();
  const RFC_3339_REGEX =
    /^(\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60))(\.\d{1,})?(([Z])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;
  // Validate the structure of the date-string
  if (!RFC_3339_REGEX.test(dateTimeString)) {
    return false;
  }
  // Check if it is a correct date using the javascript Date parse() method.
  const time = Date.parse(dateTimeString);
  if (time !== time) {
        // eslint-disable-line
    return false;
  }
  // Split the date-time-string up into the string-date and time-string part.
  // and check whether these parts are RFC 3339 compliant.
  const index = dateTimeString.indexOf('T');
  const dateString = dateTimeString.substr(0, index);
  const timeString = dateTimeString.substr(index + 1);
  return validateDate(dateString) && validateTime(timeString);
};

const validateTime = (time) => {
  time = time === null || time === void 0 ? void 0 : time.toUpperCase();
  const TIME_REGEX =
    /^([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(\.\d{1,})?(([Z])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;
  return TIME_REGEX.test(time);
};

const parseDateTime = (dateTime) => {
  return new Date(dateTime);
};

export const DateTimeScalar = new GraphQLScalarType({
  name: 'Timestamp',
  description: `DarkLight implementation of the DateTime GraphQL Scalar provided by graphql-scalars library without changing data value to Date object.`,
  serialize(value) {
    if (value instanceof Date) {
      if (validateJSDate(value)) {
        return value;
      }
      throw new TypeError('Timestamp cannot represent an invalid Date instance');
    } else if (typeof value === 'string') {
      if (validateDateTime(value)) {
        return value;
      }
      throw new TypeError(`Timestamp cannot represent an invalid date-time-string ${value}.`);
    } else if (typeof value === 'number') {
      try {
        return new Date(value).toISOString();
      } catch (e) {
        throw new TypeError(`Timestamp cannot represent an invalid Unix timestamp ${value}`);
      }
    } else {
      throw new TypeError(
        `${'Timestamp cannot be serialized from a non string, ' + 'non numeric or non Date type '}${JSON.stringify(
          value
        )}`
      );
    }
  },
  parseValue(value) {
    if (value instanceof Date) {
      if (validateJSDate(value)) {
        return value.toISOString();
      }
      throw new TypeError('Timestamp cannot represent an invalid Date instance');
    }
    if (typeof value === 'string') {
      if (validateDateTime(value)) {
        return value;
      }
      throw new TypeError(`Timestamp cannot represent an invalid date-time-string ${value}.`);
    }
    throw new TypeError(`Timestamp cannot represent non string or Date type ${JSON.stringify(value)}`);
  },
  parseLiteral(ast) {
    if (ast.kind !== Kind.STRING) {
      throw new TypeError(`Timestamp cannot represent non string or Date type ${'value' in ast && ast.value}`);
    }
    const { value } = ast;
    if (validateDateTime(value)) {
      return value;
    }
    throw new TypeError(`Timestamp cannot represent an invalid date-time-string ${String(value)}.`);
  },
});
