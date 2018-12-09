const colors = [
  '#EF5350',
  '#AB47BC',
  '#EC407A',
  '#7E57C2',
  '#5C6BC0',
  '#42A5F5',
  '#26A69A',
  '#66BB6A',
];

export const pickColor = index => colors[index];

export const stringToColour = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  let colour = '#';
  for (let i = 0; i < 3; i++) {
    const value = (hash >> (i * 8)) & 0xFF;
    colour += (`00${value.toString(16)}`).substr(-2);
  }
  return colour;
};