# Setting Up Machine Learning Models for CAPTCHA Resolution

This guide will help you set up the machine learning models that were copied from the Python project to work with the JavaScript CAPTCHA resolver.

## Quick Start

### 1. Models Already Copied

The following model files have been copied to your JavaScript project:
- `models/baseline/first_model.h5` (21MB) - TensorFlow baseline model
- `models/yolo-classification/best.pt` (2.9MB) - YOLO classification model  
- `models/yolo-segmentation/yolov8n-seg.pt` (6.7MB) - YOLO segmentation model

### 2. Install Required Dependencies

```bash
cd /Users/sam/Windows/Jetbrains_Projects/WebStorm/captcha-resolver-backend
npm install @tensorflow/tfjs-node @tensorflow/tfjs-converter onnxruntime-node sharp jimp
```

### 3. Convert PyTorch Models to ONNX

First, ensure you have the necessary Python packages:

```bash
pip install ultralytics onnx onnxruntime
```

Then run the conversion script:

```bash
python3 convert_models.py
```

This will create:
- `models/yolo-classification/best.onnx`
- `models/yolo-segmentation/yolov8n-seg.onnx`

### 4. (Optional) Convert TensorFlow Model

If the .h5 model doesn't load directly in Node.js, convert it to TensorFlow.js format:

```bash
pip install tensorflowjs tensorflow
python3 convert_tf_model.py
```

This creates `models/baseline/tfjs_model/` with the converted model.

## Usage Example

### Basic Prediction

```javascript
import CaptchaPredictor from './predict/captcha_predictor.mjs';

// Initialize predictor
const predictor = new CaptchaPredictor();
await predictor.loadModels();

// Predict a single image
const result = await predictor.predict('path/to/image.jpg');
console.log(`Predicted: ${result.className} (${(result.confidence * 100).toFixed(1)}%)`);
```

### Integration with reCAPTCHA Solver

```javascript
import { initMLSolver, solveClassificationChallenge } from './pmcaptcha/ml_solver.mjs';

// Initialize ML solver
await initMLSolver();

// Example: Solve a 3x3 tile challenge
const tileImages = [/* array of 9 image buffers or paths */];
const targetClass = 'bicycle'; // What to look for
const selectedTiles = await solveClassificationChallenge(tileImages, targetClass);

console.log('Selected tiles:', selectedTiles); // e.g., [0, 4, 7]
```

### Test the Setup

Run the test script to verify everything is working:

```bash
node predict/test_predictor.mjs
```

## File Structure

```
captcha-resolver-backend/
├── models/
│   ├── baseline/
│   │   ├── first_model.h5          # Original TensorFlow model
│   │   └── tfjs_model/             # (Optional) Converted TF.js model
│   ├── yolo-classification/
│   │   ├── best.pt                 # Original PyTorch model
│   │   └── best.onnx               # Converted ONNX model
│   └── yolo-segmentation/
│       ├── yolov8n-seg.pt          # Original PyTorch model
│       └── yolov8n-seg.onnx        # Converted ONNX model
├── predict/
│   ├── captcha_predictor.mjs      # Core prediction module
│   ├── test_predictor.mjs         # Test script
│   └── README.md                   # Detailed documentation
├── pmcaptcha/
│   └── ml_solver.mjs              # ML integration for CAPTCHA solving
├── convert_models.py              # PyTorch to ONNX converter
└── convert_tf_model.py            # TensorFlow to TF.js converter
```

## Model Capabilities

### Baseline Model
- Input: 224x224 RGB images
- Output: 12 class probabilities
- Best for: General classification tasks

### YOLO Classification Model  
- Input: 640x640 RGB images
- Output: 12 class probabilities
- Best for: Higher accuracy classification

### YOLO Segmentation Model
- Input: Any size image
- Output: 4x4 grid showing object locations
- Best for: "Select all squares with..." challenges

## Troubleshooting

### Model Loading Issues

1. **ONNX models not found**: Make sure you ran `convert_models.py`
2. **TensorFlow model fails**: Try converting to TF.js format
3. **Out of memory**: Models are large; ensure sufficient RAM

### Conversion Issues

1. **ultralytics not found**: Install with `pip install ultralytics`
2. **ONNX export fails**: Update ultralytics: `pip install --upgrade ultralytics`
3. **TensorFlow conversion fails**: Ensure TensorFlow 2.x is installed

### Performance Issues

1. Load models once at startup
2. Reuse the predictor instance
3. Process images in batches when possible
4. Consider using only one model type if memory is limited

## Next Steps

1. Integrate the ML solver with your existing reCAPTCHA code
2. Fine-tune the confidence thresholds for your use case
3. Consider training custom models for better accuracy
4. Monitor performance and adjust image preprocessing as needed 