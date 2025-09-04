# CAPTCHA Predictor Module

This module provides JavaScript functions to predict reCAPTCHA images using machine learning models ported from the Python implementation.

## Models

The module supports three types of models:

1. **Baseline Model**: TensorFlow model for general classification (224x224 images)
2. **YOLO Classification Model**: YOLO model for improved classification (640x640 images)
3. **YOLO Segmentation Model**: YOLO model for grid-based segmentation tasks

## Setup

### 1. Install Dependencies

```bash
npm install @tensorflow/tfjs-node @tensorflow/tfjs-converter onnxruntime-node sharp jimp
```

### 2. Copy Models

The models have already been copied from the Python project:
- `models/baseline/first_model.h5` - Baseline TensorFlow model
- `models/yolo-classification/best.pt` - YOLO classification model
- `models/yolo-segmentation/yolov8n-seg.pt` - YOLO segmentation model

### 3. Convert Models

#### Convert PyTorch Models to ONNX

Run the conversion script from the project root:

```bash
python3 convert_models.py
```

This will create:
- `models/yolo-classification/best.onnx`
- `models/yolo-segmentation/yolov8n-seg.onnx`

#### Convert TensorFlow Model to TensorFlow.js (Optional)

If the .h5 model doesn't load directly, convert it to TensorFlow.js format:

```bash
pip install tensorflowjs tensorflow
python3 convert_tf_model.py
```

This will create `models/baseline/tfjs_model/` directory with the converted model.

## Usage

### Basic Example

```javascript
import CaptchaPredictor from './predict/captcha_predictor.mjs';

// Create predictor instance
const predictor = new CaptchaPredictor();

// Load models (only needs to be done once)
await predictor.loadModels();

// Predict a single tile
const result = await predictor.predict('path/to/tile.jpg');
console.log(`Predicted class: ${result.className}`);
console.log(`Confidence: ${(result.probabilities[result.classIndex] * 100).toFixed(2)}%`);
```

### Classification Tasks

```javascript
// Use specific model
const baselineResult = await predictor.predict(imagePath, { model: 'baseline' });
const yoloResult = await predictor.predict(imagePath, { model: 'yolo' });

// Auto-select best available model (default)
const autoResult = await predictor.predict(imagePath);
```

### Segmentation Tasks

```javascript
// Check which grid cells contain a specific object class
const classIndex = 0; // 0 = bicycle
const segmentResult = await predictor.predictYoloSegmentation(classIndex, imagePath);

console.log(`Class found: ${segmentResult.classFound}`);
console.log("Grid (4x4):");
segmentResult.grid.forEach(row => {
    console.log(row.map(cell => cell ? "■" : "□").join(" "));
});
```

### Process Multiple Tiles

```javascript
async function processCaptchaTiles(tilePaths, targetClass) {
    const predictor = new CaptchaPredictor();
    await predictor.loadModels();
    
    const results = [];
    
    for (let i = 0; i < tilePaths.length; i++) {
        const result = await predictor.predict(tilePaths[i]);
        if (result.className === targetClass) {
            results.push(i);
        }
    }
    
    return results; // Indices of tiles containing the target class
}
```

## Class Names

The models recognize the following classes:

```javascript
const CLASSES = [
    "bicycle", "bridge", "bus", "car",
    "chimney", "crosswalk", "hydrant", "motorcycle",
    "other", "palm", "stairs", "traffic"
];
```

Note: YOLO models use slightly different class names (includes "mountain" instead of "stairs").

## Testing

Run the test script to verify everything is working:

```bash
node predict/test_predictor.mjs
```

Make sure to update the `testImagePath` in the test script with an actual image path.

## Troubleshooting

1. **Model not loading**: Ensure all model files are in the correct directories
2. **ONNX conversion fails**: Install `ultralytics` package: `pip install ultralytics`
3. **TensorFlow.js issues**: Try converting the .h5 model to TensorFlow.js format
4. **Memory issues**: Models are loaded once and reused. Dispose of tensors properly after use.

## Performance Tips

1. Load models once at startup and reuse the predictor instance
2. Process images in batches when possible
3. Use the YOLO models for better accuracy
4. Consider using smaller image sizes if performance is critical 