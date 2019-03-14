import moment from 'moment/moment';

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  const startDateParsed = moment(startDate);
  const endDateParsed = moment(endDate);
  let dateFormat = null;

  switch (interval) {
    case 'year':
      dateFormat = 'YYYY';
      break;
    case 'month':
      dateFormat = 'YYYY-MM';
      break;
    default:
      dateFormat = 'YYYY-MM-DD';
  }

  const elementsOfInterval = endDateParsed.diff(
    startDateParsed,
    `${interval}s`,
    false
  );

  const newData = [];
  for (let i = 0; i <= elementsOfInterval; i++) {
    let value = 0;
    for (let j = 0; j < data.length; j++) {
      if (data[j].date === startDateParsed.format(dateFormat)) {
        value = data[j].value;
      }
    }
    newData[i] = {
      date: startDateParsed.startOf(interval).format(),
      value
    };
    startDateParsed.add(1, `${interval}s`);
  }
  return newData;
};

export const later = delay =>
  new Promise(resolve => {
    setTimeout(resolve, delay);
  });

export const randomKey = number => {
  let key = '';
  for (let i = 0; i < number; i++) {
    key += Math.floor(Math.random() * 10).toString();
  }
  return key;
};
