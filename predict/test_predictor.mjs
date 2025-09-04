import CaptchaPredictor from './captcha_predictor.mjs';
import { CLASSES, YOLO_CLASSES } from './captcha_predictor.mjs';

async function testPredictor() {
    console.log("=== CAPTCHA Predictor Test ===\n");
    
    // Create predictor instance
    const predictor = new CaptchaPredictor();
    
    // Load models
    console.log("Loading models...");
    await predictor.loadModels();
    console.log("\n");
    
    // Test data - you'll need to provide actual image paths
    const testImagePath = "test_images/sample_tile.jpg"; // Replace with actual path
    
    try {
        // Test 1: Baseline model prediction
        console.log("Test 1: Baseline Model Prediction");
        console.log("-".repeat(40));
        
        if (predictor.baselineModel) {
            const baselineResult = await predictor.predictBaseline(testImagePath);
            console.log(`Predicted class: ${baselineResult.className}`);
            console.log(`Class index: ${baselineResult.classIndex}`);
            console.log(`Confidence: ${(baselineResult.probabilities[baselineResult.classIndex] * 100).toFixed(2)}%`);
            console.log("\nAll probabilities:");
            CLASSES.forEach((className, idx) => {
                console.log(`  ${className}: ${(baselineResult.probabilities[idx] * 100).toFixed(2)}%`);
            });
        } else {
            console.log("Baseline model not available");
        }
        
        console.log("\n");
        
        // Test 2: YOLO classification prediction
        console.log("Test 2: YOLO Classification Prediction");
        console.log("-".repeat(40));
        
        if (predictor.yoloClassificationSession) {
            const yoloResult = await predictor.predictYoloClassification(testImagePath);
            console.log(`Predicted class: ${yoloResult.className}`);
            console.log(`Class index: ${yoloResult.classIndex}`);
            console.log(`Confidence: ${(yoloResult.probabilities[yoloResult.classIndex] * 100).toFixed(2)}%`);
            console.log("\nTop 3 predictions:");
            const sortedIndices = yoloResult.probabilities
                .map((prob, idx) => ({ prob, idx }))
                .sort((a, b) => b.prob - a.prob)
                .slice(0, 3);
            sortedIndices.forEach(({ prob, idx }) => {
                console.log(`  ${YOLO_CLASSES[idx]}: ${(prob * 100).toFixed(2)}%`);
            });
        } else {
            console.log("YOLO classification model not available");
        }
        
        console.log("\n");
        
        // Test 3: YOLO segmentation prediction
        console.log("Test 3: YOLO Segmentation Prediction");
        console.log("-".repeat(40));
        
        if (predictor.yoloSegmentationSession) {
            // Test for "bicycle" class (index 0)
            const segmentationResult = await predictor.predictYoloSegmentation(0, testImagePath);
            console.log(`Class found: ${segmentationResult.classFound}`);
            console.log("Grid representation (4x4):");
            segmentationResult.grid.forEach(row => {
                console.log("  " + row.map(cell => cell ? "■" : "□").join(" "));
            });
        } else {
            console.log("YOLO segmentation model not available");
        }
        
        console.log("\n");
        
        // Test 4: Unified predict function
        console.log("Test 4: Unified Predict Function");
        console.log("-".repeat(40));
        
        const autoResult = await predictor.predict(testImagePath);
        console.log(`Predicted class: ${autoResult.className}`);
        console.log(`Model used: ${predictor.yoloClassificationSession ? 'YOLO' : 'Baseline'}`);
        
    } catch (error) {
        console.error("Error during prediction:", error);
    }
}

// Example: Process multiple tiles from a CAPTCHA challenge
async function processCaptchaTiles(tilesPaths) {
    const predictor = new CaptchaPredictor();
    await predictor.loadModels();
    
    const results = [];
    
    for (let i = 0; i < tilesPaths.length; i++) {
        const tilePath = tilesPaths[i];
        try {
            const result = await predictor.predict(tilePath, { model: 'yolo' });
            results.push({
                tileIndex: i,
                className: result.className,
                confidence: result.probabilities[result.classIndex]
            });
        } catch (error) {
            console.error(`Error processing tile ${i}:`, error);
        }
    }
    
    return results;
}

// Run the test
if (import.meta.url === `file://${process.argv[1]}`) {
    testPredictor().catch(console.error);
} 