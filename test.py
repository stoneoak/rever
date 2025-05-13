import ollama
import click

@click.command()
@click.argument("in_path", type=click.Path(exists=True))
def main(in_path):
    # Get c source code from in_path
    with open(in_path, 'r') as file:
        c_code = file.read()

    response = ollama.generate(
        model='gemma3',
        prompt=f"""Analyze the C code found in {c_code} and explain:
    1. What does this code do?
    2. Key functions and their purposes
    3. Important variables and data structures
    4. The overall logic flow
    5. Find malicious functionality?
    6. Find obfuscation techniques?
    7. Find potential security issues?
    """
    )
#     prompt=f"""Analyze the C code found in {c_code} and explain:
# 1. Find malicious functionality?
# 2. Find obfuscation techniques?
# 3. Find potential security issues?
# 4. Find potential performance issues?
# 5. Find potential memory issues?
# 6. Find potential code duplication?
# 7. Find potential code readability issues?
# """
#     prompt=f"""Analyze the C code found in {c_code} and explain:
# 1. Find malicious functionality?
# 2. Find obfuscation techniques?
# 3. Find potential security issues?
# """
#     )
    print(response['response'])


if __name__ == "__main__":
    main()

# from agno.agent import Agent
# # from dotenv import load_dotenv
# import os

# # load_dotenv()
# # print(f"os.getenv('OPENAI_API_KEY'): {os.getenv('OPENAI_API_KEY')}")

# agent = Agent(markdown=True, monitoring=True)
# agent.print_response("Share a 2 sentence horror story")