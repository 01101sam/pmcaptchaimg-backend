#!/usr/bin/env python3
"""
Convert PyTorch models to ONNX format for use in JavaScript
"""

import os
from ultralytics import YOLO


def convert_yolo_to_onnx(model_path, output_path):
    """Convert YOLO model to ONNX format."""
    print(f"Converting {model_path} to ONNX...")
    
    # Load the YOLO model
    model = YOLO(model_path)
    
    # Export to ONNX
    model.export(format='onnx', imgsz=640, simplify=True)
    
    # Move the exported file to the desired location
    base_name = os.path.splitext(os.path.basename(model_path))[0]
    onnx_file = base_name + '.onnx'
    
    if os.path.exists(onnx_file):
        os.rename(onnx_file, output_path)
        print(f"Successfully converted to {output_path}")
    else:
        print("Error: ONNX file not found after export")


def main():
    """Main function to convert all models."""
    # Convert YOLO Classification model
    convert_yolo_to_onnx(
        'models/yolo-classification/best.pt',
        'models/yolo-classification/best.onnx'
    )
    
    # Convert YOLO Segmentation model
    convert_yolo_to_onnx(
        'models/yolo-segmentation/yolov8n-seg.pt',
        'models/yolo-segmentation/yolov8n-seg.onnx'
    )
    
    print("\nAll models converted successfully!")


if __name__ == "__main__":
    main() 