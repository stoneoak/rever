from agno.agent import Agent
from agno.models.ollama import Ollama
import r2pipe
import pydotplus
import networkx as nx
import click
import json
import os
from os.path import join, basename, dirname, realpath, isdir, isfile
import shutil
import ollama

agent = Agent(
    model=Ollama(id="gemma3", provider="Ollama"),
    description="You are an expert reverse engineer and developer "
        "with 30 years of experience "
        "working on files from various operating systems and "
        "devices. You have the strong ability to understand functions "
        "and identify structures within source code.",
    #markdown=True
)
# agent.print_response("Tell me about a breaking news story from New York.", stream=True)


class TargetFile:
    def __init__(self, fpath):
        self.r2_pipe = r2pipe.open(fpath)
        self.file_path = fpath
        self.dot_outfile = f"{fpath}.dot"
        self.file_info = list()
        self.func_list = list()
        self.decomp_funcs = dict()
        # self.decomp_funcs2 = dict()
        self.decomp_funcs2 = list()
        self.nx_graph = None
        self.gv_graph = None
        self.out_path = None

        self.r2_pipe.cmd('aaa')

    def get_function_list(self):
        # Output will look like this:
        #   [ {'offset': 4195760,
        #      'name': 'main',
        #      'size': 184,
        #      ...},
        #     {'offset': 4195944,
        #      'name': 'sub_4195944',
        #      'size': 184,
        #      ...},
        #     ...
        #   ]
        self.func_list = self.r2_pipe.cmdj("aflj")

    def decompile_funcs(self, ask_llm=False):
        print(">>>>IN decompile_funcs")
        # for func in self.func_list:
        #     print(f"Decompiling function: {func['name']}({func['offset']})")
        #     self.decomp_funcs[func['offset']] = self.r2_pipe.cmd(f"s @ {func['offset']}; pdg")

        for func in self.func_list:
            print(f"Decompiling function: {func['name']}({func['offset']})")
            decomp_code = self.r2_pipe.cmd(f"s @ {func['offset']}; pdg")
            print(f">>>>Decompiled code:\n{decomp_code}")
            if ask_llm:
                response = self.rewrite_decomp_code(decomp_code)
                # decomp_code = response.content.decode('utf-8')
                decomp_code = response.content
                print(f">>>>Rewritten decompiled code:\n{decomp_code}")
                # for chunk in decomp_code:
                #     print(f">>>>Rewritten decompiled code:\n{chunk}")
            # self.decomp_funcs2.update({'offset' : hex(func['offset']),
            #                            'name' : func['name'],
            #                             'decomp_code' : decomp_code})
            self.decomp_funcs2.append({'offset' : hex(func['offset']),
                                       'name' : func['name'],
                                        'decomp_code' : decomp_code})
        print()
        print(f">>>>Decompiled functions:\n{self.decomp_funcs2}")
        print()
            
    def write_output_single_file(self):
        # Write self.decomp_funcs to a single file  
        self.out_path = f"{self.file_path}_funcs_r2.json"
        if isfile(self.out_path):
            os.unlink(self.out_path)
        with open(self.out_path, "w") as f:
            # f.write(json.dumps(self.decomp_funcs))
            json.dump(self.decomp_funcs2, f, indent=4)

        if isfile(self.out_path):
            print(f"JSON output of decompiled functions saved to {self.out_path}")
        else:
            print(f"[ERROR] Failed to write JSON output of decompiled functions.")

    def write_output_multiple_files(self):
        # Write each decompiled functions in self.decomp_funcs to a separate file
        # Create a directory for the output files
        dir_name = dirname(self.file_path)
        self.out_path = join(dir_name, f"{basename(self.file_path)}_funcs_r2")
        if isdir(self.out_path):
            # Delete the directory and all its contents
            shutil.rmtree(self.out_path)
        # Make a new directory to house the func files
        os.mkdir(self.out_path)

        # Write files to a new directory
        for func in self.decomp_funcs2:
            tmp_path = join(self.out_path, f"{func['name']}.c")
            with open(tmp_path, "w") as f:
                f.write(func['decompiled_code'])

        if isdir(self.out_path):
            print(f"Decompiled functions saved to {self.out_path}")
        else:
            print(f"[ERROR] Failed to write decompiled functions.")

    def cleanup(self):
        self.r2_pipe.quit()

    def rewrite_decomp_code(self, decomp_code):
        # response = ollama.generate(
        #     model='gemma3',
        #     prompt=f"""Rewrite this function found in {decomp_code} and respond ONLY with code, replace goto/labels
		# with if/else/for, use NO explanations, NO markdown, Simplify as much as
		# possible, use better variable names, take function arguments and
		# strings from comments like 'string:'"""
        # )
        # return response['response']
        # agent.print_response(f"""Rewrite this function found in {decomp_code} and respond ONLY with code, replace goto/labels
		# with if/else/for, use NO explanations, NO markdown, Simplify as much as
		# possible, use better variable names, take function arguments and
		# strings from comments like 'string:'""", stream=True)

        run_response = agent.run(f"""Rewrite this function found in {decomp_code} and respond ONLY with code, replace goto/labels
		with if/else/for, use NO explanations, NO markdown, Simplify as much as
		possible, use better variable names, take function arguments and
		strings from comments like 'string:'""", stream=False)
        return run_response

    def explain_code(self):
        # Create a directory for the output files
        dir_name = dirname(self.file_path)
        explanations_dir = join(dir_name, f"{basename(self.file_path)}_explanations")
        if isdir(explanations_dir):
            # Delete the directory and all its contents
            shutil.rmtree(explanations_dir)
        # Make a new directory to house the func files
        os.mkdir(explanations_dir)

        # Load the JSON file
        with open(self.out_path, 'r') as file:
            decompiled_funcs = json.load(file)

        # Get 'decomp_code' from each function in decompiled_funcs
        for func in decompiled_funcs:
            decomp_code = func['decomp_code']
            func_name = func['name']
            func_offset = func['offset']
        #     agent.print_response(f"""Analyze the C code found in {decomp_code} and explain:
        # 1. What does this code do?
        # 2. Key functions and their purposes
        # 3. Important variables and data structures
        # 4. The overall logic flow
        # 5. Find malicious functionality?
        # 6. Find obfuscation techniques?
        # 7. Find potential security issues?
        # """, stream=True)
            print(f">>>>Searching {func_name} ({func_offset}):\n{decomp_code}")
            run_response = agent.run(f"""Analyze the C code found in {decomp_code} and explain:
        1. What does this code do?
        2. Key functions and their purposes
        3. Important variables and data structures
        4. The overall logic flow
        5. Find malicious functionality?
        6. Find obfuscation techniques?
        7. Find potential security issues?
        """, stream=False)
            
            # explained_code = run_response.content.decode('utf-8')
            explained_code = run_response.content
            print(f">>>>Explained code:\n{explained_code}")
            func['explained_code'] = explained_code
            with open(join(explanations_dir, f"{func_name}.txt"), "w") as f:
                f.write(explained_code)       
        
    #     # Get c source code from in_path
    #     with open(self.out_path, 'r') as file:
    #         c_code = file.read()

    #     # Get the function list
    #     with open(self.out_path, 'r') as file:
    #         func_list = file.read()

    #     agent.print_response(f"""Analyze the C code found in {c_code} and explain:
    #     1. What does this code do?
    #     2. Key functions and their purposes
    #     3. Important variables and data structures
    #     4. The overall logic flow
    #     5. Find malicious functionality?
    #     6. Find obfuscation techniques?
    #     7. Find potential security issues?
    #     """, stream=True)
    #     # response = ollama.generate(
    #     #     model='gemma3',
    #     #     prompt=f"""Analyze the C code found in {c_code} and explain:
    #     # 1. What does this code do?
    #     # 2. Key functions and their purposes
    #     # 3. Important variables and data structures
    #     # 4. The overall logic flow
    #     # 5. Find malicious functionality?
    #     # 6. Find obfuscation techniques?
    #     # 7. Find potential security issues?
    #     # """
    #     # )
    # #     prompt=f"""Analyze the C code found in {c_code} and explain:
    # # 1. Find malicious functionality?
    # # 2. Find obfuscation techniques?
    # # 3. Find potential security issues?
    # # 4. Find potential performance issues?
    # # 5. Find potential memory issues?
    # # 6. Find potential code duplication?
    # # 7. Find potential code readability issues?
    # # """
    # #     prompt=f"""Analyze the C code found in {c_code} and explain:
    # # 1. Find malicious functionality?
    # # 2. Find obfuscation techniques?
    # # 3. Find potential security issues?
    # # """
    # #     )
    #     # print(response['response'])

    # TODO: Untested!! NEED TO TEST
    def build_call_graph(self):
        self.gv_graph = self.r2_pipe("agCd")
        # Write the contents of the graph to a graphviz file
        with open(self.dot_outfile, "w") as f:
            f.write(self.gv_graph)
        # Convert the graphviz file to a networkx graph (MultiDiGraph)
        dotplus = pydotplus.graph_from_dot_data(self.gv_graph)
        self.nx_graph = nx.nx_pydot.from_pydot(dotplus)
        # Create PNG file
        png_cmd = f"!!dot -Tpng -o {self.dot_outfile}.png {self.dot_outfile}"
        self.r2_pipe.cmd(png_cmd)


@click.command()
@click.argument("in_path", type=click.Path(exists=True))
def main(in_path):
    bin_file = TargetFile(in_path)
    bin_file.get_function_list()
    bin_file.decompile_funcs(ask_llm=True)
    bin_file.write_output_single_file()
    # bin_file.write_output_multiple_files()
    # bin_file.build_call_graph()
    bin_file.explain_code()

    bin_file.cleanup()

if __name__ == "__main__":
    main()