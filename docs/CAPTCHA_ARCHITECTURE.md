# Captcha Resolver Architecture

## Overview

This project now supports two distinct image-based captcha types, with audio functionality preserved for future reference but no longer actively used.

## Captcha Types

### 1. Image Object Recognition (`CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION`)
- **Description**: Grid-based captchas where users need to identify specific objects (e.g., "Select all traffic lights")
- **Google Types**: `imageselect`
- **Metadata**: Uses `ParamMetadata` class with object labels and grid information
- **Processing**: Splits images into tiles and requires object detection

### 2. Image Grid Challenge (`CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE`)
- **Description**: More complex grid-based challenges (e.g., multi-captcha, tile selection)
- **Google Types**: `tileselect`, `multicaptcha`
- **Metadata**: Similar to object recognition but may have different selection criteria
- **Processing**: Uses image splitting and pattern recognition

### 3. Audio (Preserved for Reference)
- **Type**: `CAPTCHA_TYPE_AUDIO`
- **Status**: Disabled but code preserved
- **Location**: Audio handling code is in `pmcaptcha/catpcha.mjs` (disabled with `false &&` condition)
- **ML Model**: `predict/automatic-speech-recognition.mjs` (kept but not used)

## Key Files

### `pmcaptcha/captcha-types.mjs`
- Defines captcha type constants
- Contains `ReloadResponse` with type mapping logic
- `ImageData` class for image manipulation
- `ParamMetadata` for challenge metadata

### `pmcaptcha/catpcha.mjs`
- Main captcha handling logic
- `RealBrowser` class intercepts requests and processes responses
- Image captcha handling in `responseCallback` method
- Audio code preserved but disabled

### `predict/image-captcha-solver.mjs`
- Placeholder for future image captcha solving logic
- Separate methods for each image type
- Ready for ML model integration

## Type Mapping

The system automatically maps Google's challenge types to our internal types:

```javascript
const typeMap = {
    'audio': CAPTCHA_TYPE_AUDIO,
    'imageselect': CAPTCHA_TYPE_IMAGE_OBJECT_RECOGNITION,
    'tileselect': CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE,
    'multicaptcha': CAPTCHA_TYPE_IMAGE_GRID_CHALLENGE,
};
```

## Future Development

1. **Image Object Recognition**: Implement ML model for object detection in tiles
2. **Grid Challenge**: Implement pattern recognition for complex grid challenges
3. **Audio**: Code is preserved and can be reactivated by removing the `false &&` condition

## Migration Notes

- The system no longer switches to audio when encountering image captchas
- Image data is now properly stored in `cached.imageData` and `cached.imageTiles`
- Effort time calculation is adjusted for image types based on grid size 