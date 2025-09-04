import * as tf from '@tensorflow/tfjs-node';
import * as ort from 'onnxruntime-node';
import sharp from 'sharp';
import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Class names for reCAPTCHA challenges
const CLASSES = [
    "bicycle",
    "bridge", 
    "bus",
    "car",
    "chimney",
    "crosswalk",
    "hydrant",
    "motorcycle",
    "other",
    "palm",
    "stairs",
    "traffic"
];

// YOLO class names (slightly different order)
const YOLO_CLASSES = [
    "bicycle",
    "bridge",
    "bus",
    "car",
    "chimney",
    "crosswalk",
    "hydrant",
    "motorcycle",
    "mountain",
    "other",
    "palm",
    "traffic"
];

// Mapping from COCO dataset class IDs to reCAPTCHA class indices
// Format: [COCO_class_id, reCAPTCHA_class_index]
const COCO_TO_CAPTCHA_MAPPING = [
    [1, 0],   // bicycle
    [5, 2],   // bus
    [2, 3],   // car
    [10, 6],  // fire hydrant
    [3, 7],   // motorcycle
    [9, 11]   // traffic light
];

class CaptchaPredictor {
    constructor() {
        this.baselineModel = null;
        this.yoloClassificationSession = null;
        this.yoloSegmentationSession = null;
        this.modelsLoaded = false;
    }

    async loadModels() {
        if (this.modelsLoaded) return;

        console.log("Loading models...");

        // Load TensorFlow baseline model
        try {
            // Try loading TensorFlow.js format first
            const tfjsModelPath = path.join(__dirname, '..', 'models', 'baseline', 'tfjs_model', 'model.json');
            if (await this.fileExists(tfjsModelPath)) {
                this.baselineModel = await tf.loadLayersModel(`file://${tfjsModelPath}`);
                console.log("Baseline model (TensorFlow.js format) loaded successfully");
            } else {
                // Fall back to .h5 format
                const h5ModelPath = path.join(__dirname, '..', 'models', 'baseline', 'first_model.h5');
                if (await this.fileExists(h5ModelPath)) {
                    this.baselineModel = await tf.loadLayersModel(`file://${h5ModelPath}`);
                    console.log("Baseline model (.h5 format) loaded successfully");
                }
            }
        } catch (error) {
            console.error("Error loading baseline model:", error);
        }

        // Load YOLO Classification model
        try {
            const onnxPath = path.join(__dirname, '..', 'models', 'yolo-classification', 'best.onnx');
            if (await this.fileExists(onnxPath)) {
                this.yoloClassificationSession = await ort.InferenceSession.create(onnxPath);
                console.log("YOLO classification model loaded successfully");
            }
        } catch (error) {
            console.error("Error loading YOLO classification model:", error);
        }

        // Load YOLO Segmentation model
        try {
            const onnxPath = path.join(__dirname, '..', 'models', 'yolo-segmentation', 'yolov8n-seg.onnx');
            if (await this.fileExists(onnxPath)) {
                this.yoloSegmentationSession = await ort.InferenceSession.create(onnxPath);
                console.log("YOLO segmentation model loaded successfully");
            }
        } catch (error) {
            console.error("Error loading YOLO segmentation model:", error);
        }

        this.modelsLoaded = true;
    }

    async fileExists(filePath) {
        try {
            await fs.access(filePath);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Predict using the baseline TensorFlow model
     * @param {string|Buffer} imagePath - Path to image file or image buffer
     * @returns {Promise<{probabilities: number[], className: string, classIndex: number}>}
     */
    async predictBaseline(imagePath) {
        if (!this.baselineModel) {
            throw new Error("Baseline model not loaded");
        }

        // Load and preprocess image
        const imageBuffer = typeof imagePath === 'string' 
            ? await fs.readFile(imagePath)
            : imagePath;

        // Resize to 224x224 and convert to tensor
        const processedImage = await sharp(imageBuffer)
            .resize(224, 224)
            .raw()
            .toBuffer();

        // Convert to tensor and normalize
        const imageTensor = tf.tensor3d(
            new Uint8Array(processedImage),
            [224, 224, 3]
        ).expandDims(0).div(255.0);

        // Make prediction
        const predictions = await this.baselineModel.predict(imageTensor);
        const probabilities = await predictions.data();
        
        // Clean up tensors
        imageTensor.dispose();
        predictions.dispose();

        // Find class with highest probability
        const maxIndex = probabilities.indexOf(Math.max(...probabilities));
        
        return {
            probabilities: Array.from(probabilities),
            className: CLASSES[maxIndex],
            classIndex: maxIndex
        };
    }

    /**
     * Predict using YOLO classification model
     * @param {string|Buffer} imagePath - Path to image file or image buffer
     * @returns {Promise<{probabilities: number[], className: string, classIndex: number}>}
     */
    async predictYoloClassification(imagePath) {
        if (!this.yoloClassificationSession) {
            throw new Error("YOLO classification model not loaded");
        }

        // Load and preprocess image
        const imageBuffer = typeof imagePath === 'string'
            ? await fs.readFile(imagePath)
            : imagePath;

        // Resize to 640x640 (YOLO default) and convert to tensor
        const processedImage = await sharp(imageBuffer)
            .resize(640, 640)
            .raw()
            .toBuffer();

        // Convert to Float32Array and normalize
        const floatData = new Float32Array(640 * 640 * 3);
        for (let i = 0; i < processedImage.length; i++) {
            floatData[i] = processedImage[i] / 255.0;
        }

        // Create ONNX tensor (NCHW format)
        const inputTensor = new ort.Tensor('float32', floatData, [1, 3, 640, 640]);

        // Run inference
        const results = await this.yoloClassificationSession.run({ images: inputTensor });
        
        // Extract probabilities (assuming output0 contains class probabilities)
        const output = results.output0 || results[Object.keys(results)[0]];
        const probabilities = output.data;

        // Find class with highest probability
        const maxIndex = probabilities.indexOf(Math.max(...probabilities));

        return {
            probabilities: Array.from(probabilities),
            className: YOLO_CLASSES[maxIndex],
            classIndex: maxIndex
        };
    }

    /**
     * Predict segmentation using YOLO segmentation model
     * @param {number} classNumber - The reCAPTCHA class index to search for
     * @param {string|Buffer} imagePath - Path to image file or image buffer
     * @returns {Promise<{classFound: boolean, grid: number[][]}>}
     */
    async predictYoloSegmentation(classNumber, imagePath) {
        if (!this.yoloSegmentationSession) {
            throw new Error("YOLO segmentation model not loaded");
        }

        // Map reCAPTCHA class to COCO class ID
        let cocoClassId = null;
        for (const [coco, captcha] of COCO_TO_CAPTCHA_MAPPING) {
            if (captcha === classNumber) {
                cocoClassId = coco;
                break;
            }
        }

        if (cocoClassId === null) {
            return { classFound: false, grid: Array(4).fill(Array(4).fill(0)) };
        }

        // Load and preprocess image
        const imageBuffer = typeof imagePath === 'string'
            ? await fs.readFile(imagePath)
            : imagePath;

        // Get original image dimensions
        const metadata = await sharp(imageBuffer).metadata();
        const originalWidth = metadata.width;
        const originalHeight = metadata.height;

        // Resize to 640x640 for YOLO
        const processedImage = await sharp(imageBuffer)
            .resize(640, 640)
            .raw()
            .toBuffer();

        // Convert to Float32Array and normalize
        const floatData = new Float32Array(640 * 640 * 3);
        for (let i = 0; i < processedImage.length; i++) {
            floatData[i] = processedImage[i] / 255.0;
        }

        // Create ONNX tensor
        const inputTensor = new ort.Tensor('float32', floatData, [1, 3, 640, 640]);

        // Run inference
        const results = await this.yoloSegmentationSession.run({ images: inputTensor });

        // Process results to create grid
        const grid = this.processSegmentationResults(
            results,
            cocoClassId,
            originalWidth,
            originalHeight
        );

        return {
            classFound: grid.some(row => row.some(cell => cell === 1)),
            grid: grid
        };
    }

    /**
     * Process segmentation results to create a 4x4 grid
     * @private
     */
    processSegmentationResults(results, targetClassId, imageWidth, imageHeight) {
        const gridSize = 4;
        const grid = Array(gridSize).fill(null).map(() => Array(gridSize).fill(0));

        // Extract detection results
        // Note: YOLO output format may vary, adjust based on actual model output
        const boxes = results.output0 || results[Object.keys(results)[0]];
        const masks = results.output1 || results[Object.keys(results)[1]];

        if (!boxes || !masks) {
            return grid;
        }

        // Process each detection
        const numDetections = boxes.dims[1];
        for (let i = 0; i < numDetections; i++) {
            // Check if this detection is for our target class
            const classId = Math.round(boxes.data[i * 6 + 5]); // Assuming class ID is at index 5
            
            if (classId === targetClassId) {
                // Get bounding box coordinates
                const x1 = boxes.data[i * 6 + 0] * imageWidth / 640;
                const y1 = boxes.data[i * 6 + 1] * imageHeight / 640;
                const x2 = boxes.data[i * 6 + 2] * imageWidth / 640;
                const y2 = boxes.data[i * 6 + 3] * imageHeight / 640;

                // Calculate which grid cells this box overlaps
                const cellWidth = imageWidth / gridSize;
                const cellHeight = imageHeight / gridSize;

                for (let row = 0; row < gridSize; row++) {
                    for (let col = 0; col < gridSize; col++) {
                        const cellX1 = col * cellWidth;
                        const cellY1 = row * cellHeight;
                        const cellX2 = cellX1 + cellWidth;
                        const cellY2 = cellY1 + cellHeight;

                        // Check if box overlaps with this cell
                        if (x1 < cellX2 && x2 > cellX1 && y1 < cellY2 && y2 > cellY1) {
                            grid[row][col] = 1;
                        }
                    }
                }
            }
        }

        return grid;
    }

    /**
     * Unified prediction function that automatically selects the best model
     * @param {string|Buffer} imagePath - Path to image file or image buffer
     * @param {Object} options - Options for prediction
     * @param {string} options.model - Model to use: 'baseline', 'yolo', or 'auto'
     * @param {number} options.classNumber - For segmentation tasks
     * @returns {Promise<Object>} Prediction results
     */
    async predict(imagePath, options = {}) {
        const { model = 'auto', classNumber } = options;

        if (!this.modelsLoaded) {
            await this.loadModels();
        }

        // For segmentation tasks
        if (classNumber !== undefined) {
            return await this.predictYoloSegmentation(classNumber, imagePath);
        }

        // For classification tasks
        switch (model) {
            case 'baseline':
                return await this.predictBaseline(imagePath);
            case 'yolo':
                return await this.predictYoloClassification(imagePath);
            case 'auto':
                // Try YOLO first, fall back to baseline
                if (this.yoloClassificationSession) {
                    return await this.predictYoloClassification(imagePath);
                } else if (this.baselineModel) {
                    return await this.predictBaseline(imagePath);
                }
                throw new Error("No models available");
            default:
                throw new Error(`Unknown model: ${model}`);
        }
    }
}

export default CaptchaPredictor;
export { CLASSES, YOLO_CLASSES, CaptchaPredictor }; 