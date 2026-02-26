import tflite_runtime.interpreter as tflite
import sys
import argparse

def dump_tflite_model(model_path, ext_delegate):
    if ext_delegate is not None:
        ext_dele = [tflite.load_delegate(ext_delegate)]
        interpreter = tflite.Interpreter(model_path=model_path, experimental_delegates=ext_dele)
    else:
        interpreter = tflite.Interpreter(model_path=model_path)
    
    interpreter.allocate_tensors()
    
    # Get input and output details
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    print("=" * 60)
    print("TFLite Model Information")
    print("=" * 60)
    print(f"Model Path: {model_path}")
    print()
    
    # Print input information
    print("Input Details:")
    print("-" * 60)
    for i, input_detail in enumerate(input_details):
        print(f"Input {i}:")
        print(f"  Name: {input_detail['name']}")
        print(f"  Shape: {input_detail['shape']}")
        print(f"  Type: {input_detail['dtype']}")
        print(f"  Index: {input_detail['index']}")
        if 'quantization' in input_detail:
            print(f"  Quantization: {input_detail['quantization']}")
        print("input detail dump:")
        print(input_detail)
        print()
    
    # Print output information
    print("Output Details:")
    print("-" * 60)
    for i, output_detail in enumerate(output_details):
        print(f"Output {i}:")
        print(f"  Name: {output_detail['name']}")
        print(f"  Shape: {output_detail['shape']}")
        print(f"  Type: {output_detail['dtype']}")
        print(f"  Index: {output_detail['index']}")
        if 'quantization' in output_detail:
            print(f"  Quantization: {output_detail['quantization']}")
        print("output detail dump:")
        print(output_detail)
        print()
    
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dump TFLite model information")
    parser.add_argument("-m", "--model_path", help="Path to the TFLite model file")
    parser.add_argument("-e", "--ext_delegate", help="external_delegate library path")
    args = parser.parse_args()
    
    dump_tflite_model(args.model_path, args.ext_delegate)