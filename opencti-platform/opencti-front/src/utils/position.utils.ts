// Default coordinates (Paris) for fallback when coordinates are invalid
export const DEFAULT_CENTER_COORDINATES: [number, number] = [48.8566969, 2.3514616];

// Validate latitude is within valid range
export const isValidLatitude = (lat: number | null | undefined): lat is number => {
  return lat !== null && lat !== undefined && lat >= -90 && lat <= 90;
};

// Validate longitude is within valid range
export const isValidLongitude = (lng: number | null | undefined): lng is number => {
  return lng !== null && lng !== undefined && lng >= -180 && lng <= 180;
};

export const isValidCoordinates = (
  coordinates: { longitude?: number | null; latitude?: number | null } | undefined | null,
): coordinates is { longitude: number; latitude: number } => {
  return isValidLongitude(coordinates?.longitude) && isValidLatitude(coordinates?.latitude);
};

// Get validated coordinates, fallback to default if invalid
export const getValidatedCenter = (position: { latitude?: number | null; longitude?: number | null }): [number, number] => {
  if (isValidCoordinates(position)) {
    return [position.latitude, position.longitude];
  }
  return DEFAULT_CENTER_COORDINATES;
};

// Validate coordinate array format
export const validateCoordinates = (coordinates: unknown): [number, number] => {
  if (!coordinates || !Array.isArray(coordinates) || coordinates.length !== 2) {
    return DEFAULT_CENTER_COORDINATES;
  }
  const [lat, lng] = coordinates;
  if (!isValidLatitude(lat) || !isValidLongitude(lng)) {
    return DEFAULT_CENTER_COORDINATES;
  }
  return [lat, lng] as [number, number];
};
