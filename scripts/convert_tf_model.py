#!/usr/bin/env python3
"""
Convert TensorFlow .h5 model to TensorFlow.js format
"""

import os
import tensorflowjs as tfjs
import tensorflow as tf


def convert_h5_to_tfjs(h5_path, output_dir):
    """Convert H5 model to TensorFlow.js format."""
    print(f"Converting {h5_path} to TensorFlow.js format...")
    
    # Load the model
    model = tf.keras.models.load_model(h5_path, compile=False)
    
    # Convert to TensorFlow.js
    tfjs.converters.save_keras_model(model, output_dir)
    
    print(f"Model converted successfully to {output_dir}")


def main():
    """Main function to convert the baseline model."""
    # Input and output paths
    h5_model_path = 'models/baseline/first_model.h5'
    output_dir = 'models/baseline/tfjs_model'
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Convert the model
    convert_h5_to_tfjs(h5_model_path, output_dir)
    
    print("\nConversion complete!")
    print(f"TensorFlow.js model saved to: {output_dir}")
    print("\nTo use in JavaScript, load with:")
    print(f"  const model = await tf.loadLayersModel("
          f"'file://{output_dir}/model.json');")


if __name__ == "__main__":
    main() 