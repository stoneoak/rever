import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import os
import click

class CCodeAnalyzer:
    def __init__(self, file_path, model_name="google/gemma-3b"):
        """
        Initialize the Gemma model for C code analysis.
        Args:
            model_name (str): The Gemma model to use (default: gemma-3b)
        """
        self.file_path = file_path
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            device_map="auto",
            torch_dtype=torch.float16
        )

    def read_c_file(self, file_path):
        """
        Read a C source code file.
        Args:
            file_path (str): Path to the C source file
        Returns:
            str: Content of the C file
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            raise Exception(f"Error reading C file: {str(e)}")

    def analyze_code(self, code, analysis_type="explain"):
        """
        Analyze C code using Gemma.
        Args:
            code (str): The C source code to analyze
            analysis_type (str): Type of analysis to perform
                               ("explain", "security", "optimization", "documentation")
        Returns:
            str: Gemma's analysis
        """
        prompts = {
            "explain": """Analyze this C code and explain:
1. What does this code do?
2. Key functions and their purposes
3. Important variables and data structures
4. The overall logic flow

C Code:
{}

Detailed Explanation:""",
            
            "security": """Review this C code for security issues:
1. Identify potential vulnerabilities
2. Point out unsafe functions or practices
3. Suggest security improvements

C Code:
{}

Security Analysis:""",
            
            "optimization": """Analyze this C code for optimization:
1. Performance bottlenecks
2. Memory usage concerns
3. Suggested optimizations

C Code:
{}

Optimization Analysis:""",
            
            "documentation": """Generate documentation for this C code:
1. Function-level documentation
2. Important parameters and return values
3. Usage examples
4. Dependencies and requirements

C Code:
{}

Documentation:"""
        }

        prompt = prompts.get(analysis_type, prompts["explain"]).format(code)

        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        
        outputs = self.model.generate(
            inputs.input_ids,
            max_length=2048,  # Increased for detailed code analysis
            temperature=0.7,
            top_p=0.9,
            do_sample=True,
            pad_token_id=self.tokenizer.pad_token_id
        )
        
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response.replace(prompt, "").strip()

    def analyze_c_file(self, file_path, analysis_types=None):
        """
        Perform multiple types of analysis on a C file.
        Args:
            file_path (str): Path to the C source file
            analysis_types (list): Types of analysis to perform
        Returns:
            dict: Analysis results for each requested type
        """
        if analysis_types is None:
            analysis_types = ["explain"]
        
        code = self.read_c_file(file_path)
        results = {}
        
        for analysis_type in analysis_types:
            results[analysis_type] = self.analyze_code(code, analysis_type)
            
        return results

@click.command()
@click.argument("in_path", type=click.Path(exists=True))
def main(in_path):
    # Example usage
    analyzer = CCodeAnalyzer(in_path)
    
    # Example file path - replace with your actual C file path
    # c_file_path = "example.c"
    
    try:
        # Perform multiple types of analysis
        analysis_results = analyzer.analyze_c_file(
            # c_file_path,
            analyzer.file_path,
            analysis_types=["explain", "security", "optimization"]
        )
        
        # Print results
        for analysis_type, result in analysis_results.items():
            print(f"\n=== {analysis_type.upper()} ANALYSIS ===")
            print(result)
            print("\n" + "="*50)
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()