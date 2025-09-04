import CaptchaPredictor from '../predict/captcha_predictor.mjs';
import { CLASSES, YOLO_CLASSES } from '../predict/captcha_predictor.mjs';

// Global predictor instance
let predictor = null;

/**
 * Initialize the ML solver by loading models
 */
export async function initMLSolver() {
    if (!predictor) {
        predictor = new CaptchaPredictor();
        await predictor.loadModels();
        console.log("ML Solver initialized");
    }
    return predictor;
}

/**
 * Solve a classification CAPTCHA challenge
 * @param {Array<Buffer|string>} tileImages - Array of tile images (buffers or paths)
 * @param {string} targetClass - The class to look for (e.g., "bicycle", "bus")
 * @param {Object} options - Additional options
 * @returns {Promise<Array<number>>} Array of tile indices that contain the target class
 */
export async function solveClassificationChallenge(tileImages, targetClass, options = {}) {
    const { threshold = 0.5, model = 'auto' } = options;
    
    // Ensure predictor is initialized
    if (!predictor) {
        await initMLSolver();
    }
    
    const selectedTiles = [];
    
    // Process each tile
    for (let i = 0; i < tileImages.length; i++) {
        try {
            const result = await predictor.predict(tileImages[i], { model });
            
            // Check if this tile contains the target class
            if (result.className === targetClass || 
                (result.className.includes(targetClass) || targetClass.includes(result.className))) {
                
                // Check confidence threshold
                if (result.probabilities[result.classIndex] >= threshold) {
                    selectedTiles.push(i);
                    console.log(`Tile ${i}: ${result.className} (${(result.probabilities[result.classIndex] * 100).toFixed(1)}%)`);
                }
            }
        } catch (error) {
            console.error(`Error processing tile ${i}:`, error);
        }
    }
    
    return selectedTiles;
}

/**
 * Solve a segmentation CAPTCHA challenge (4x4 grid)
 * @param {Buffer|string} gridImage - The full grid image
 * @param {string} targetClass - The class to look for
 * @returns {Promise<{grid: number[][], selectedCells: Array<{row: number, col: number}>}>}
 */
export async function solveSegmentationChallenge(gridImage, targetClass) {
    // Ensure predictor is initialized
    if (!predictor) {
        await initMLSolver();
    }
    
    // Find the class index
    let classIndex = CLASSES.indexOf(targetClass);
    if (classIndex === -1) {
        // Try YOLO classes
        classIndex = YOLO_CLASSES.indexOf(targetClass);
        if (classIndex === -1) {
            throw new Error(`Unknown class: ${targetClass}`);
        }
    }
    
    // Get segmentation result
    const result = await predictor.predictYoloSegmentation(classIndex, gridImage);
    
    // Convert grid to cell coordinates
    const selectedCells = [];
    for (let row = 0; row < result.grid.length; row++) {
        for (let col = 0; col < result.grid[row].length; col++) {
            if (result.grid[row][col] === 1) {
                selectedCells.push({ row, col });
            }
        }
    }
    
    return {
        grid: result.grid,
        selectedCells,
        classFound: result.classFound
    };
}

/**
 * Solve dynamic CAPTCHA challenge (tiles that refresh)
 * @param {Buffer|string} tileImage - Single tile image
 * @param {string} targetClass - The class to look for
 * @param {Object} options - Additional options
 * @returns {Promise<{isMatch: boolean, confidence: number, className: string}>}
 */
export async function checkDynamicTile(tileImage, targetClass, options = {}) {
    const { threshold = 0.5, model = 'auto' } = options;
    
    // Ensure predictor is initialized
    if (!predictor) {
        await initMLSolver();
    }
    
    const result = await predictor.predict(tileImage, { model });
    
    const isMatch = result.className === targetClass || 
                    (result.className.includes(targetClass) || targetClass.includes(result.className));
    
    return {
        isMatch: isMatch && result.probabilities[result.classIndex] >= threshold,
        confidence: result.probabilities[result.classIndex],
        className: result.className
    };
}

/**
 * Extract target class from CAPTCHA challenge text
 * @param {string} challengeText - The challenge text (e.g., "Select all images with bicycles")
 * @returns {string|null} The extracted class name or null if not found
 */
export function extractTargetClass(challengeText) {
    const lowerText = challengeText.toLowerCase();
    
    // Check each known class
    for (const className of CLASSES) {
        if (lowerText.includes(className)) {
            return className;
        }
        
        // Handle plurals
        if (lowerText.includes(className + 's')) {
            return className;
        }
        
        // Handle special cases
        if (className === 'traffic' && lowerText.includes('traffic light')) {
            return 'traffic';
        }
        if (className === 'hydrant' && lowerText.includes('fire hydrant')) {
            return 'hydrant';
        }
    }
    
    return null;
}

/**
 * Get confidence scores for all classes for a given image
 * @param {Buffer|string} image - Image to analyze
 * @param {Object} options - Additional options
 * @returns {Promise<Array<{className: string, confidence: number}>>}
 */
export async function getClassConfidences(image, options = {}) {
    const { model = 'auto' } = options;
    
    // Ensure predictor is initialized
    if (!predictor) {
        await initMLSolver();
    }
    
    const result = await predictor.predict(image, { model });
    const classes = model === 'yolo' ? YOLO_CLASSES : CLASSES;
    
    return classes.map((className, idx) => ({
        className,
        confidence: result.probabilities[idx] || 0
    })).sort((a, b) => b.confidence - a.confidence);
}

export default {
    initMLSolver,
    solveClassificationChallenge,
    solveSegmentationChallenge,
    checkDynamicTile,
    extractTargetClass,
    getClassConfidences
}; 