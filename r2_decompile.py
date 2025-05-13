import r2pipe
import pydotplus
import networkx as nx
import click
import json
import os
from os.path import join, basename, dirname, realpath, isdir, isfile
import shutil

class TargetFile:
    def __init__(self, fpath):
        self.r2_pipe = r2pipe.open(fpath)
        self.file_path = fpath
        self.dot_outfile = f"{fpath}.dot"
        self.file_info = list()
        self.func_list = list()
        self.decomp_funcs = dict()
        self.decomp_funcs2 = dict()
        self.nx_graph = None
        self.gv_graph = None

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
        self.func_list = self.r2_pipe.cmdj("afl")

    def decompile_funcs(self):
        # for func in self.func_list:
        #     print(f"Decompiling function: {func['name']}({func['offset']})")
        #     self.decomp_funcs[func['offset']] = self.r2_pipe.cmd(f"s @ {func['offset']}; pdg")

        for func in self.func_list:
            print(f"Decompiling function: {func['name']}({func['offset']})")
            decomp_code = self.r2_pipe.cmd(f"s @ {func['offset']}; pdg")
            self.decomp_funcs2.append({'offset' : hex(func['offset']),
                                       'name' : func['name'],
                                        'decomp_code' : decomp_code})
            
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

    def write_output_single_file(self):
        # Write self.decomp_funcs to a single file
        out_path = f"{self.file_path}_funcs_r2.json"
        if isfile(out_path):
            os.unlink(out_path)
        with open(out_path, "w") as f:
            # f.write(json.dumps(self.decomp_funcs))
            json.dump(self.decomp_funcs2, f, indent=4)

        if isfile(out_path):
            print(f"JSON output of decompiled functions saved to {out_path}")
        else:
            print(f"[ERROR] Failed to write JSON output of decompiled functions.")

    def write_output_multiple_files(self):
        # Write each decompiled functions in self.decomp_funcs to a separate file
        # Create a directory for the output files
        dir_name = dirname(self.file_path)
        output_path = join(dir_name, f"{basename(self.file_path)}_funcs_r2")
        if isdir(output_path):
            # Delete the directory and all its contents
            shutil.rmtree(output_path)
        # Make a new directory to house the func files
        os.mkdir(output_path)

        # Write files to a new directory
        for func in self.decomp_funcs2:
            tmp_path = join(output_path, f"{func['name']}.c")
            with open(tmp_path, "w") as f:
                f.write(func['decompiled_code'])

        if isdir(output_path):
            print(f"Decompiled functions saved to {output_path}")
        else:
            print(f"[ERROR] Failed to write decompiled functions.")

    def cleanup(self):
        self.r2_pipe.quit()

@click.command()
@click.argument("in_path", type=click.Path(exists=True))
def main(in_path):
    bin_file = TargetFile(in_path)
    bin_file.get_function_list
    bin_file.decompile_funcs()
    bin_file.write_output_single_file()
    # bin_file.write_output_multiple_files()
    # bin_file.build_call_graph()

    bin_file.cleanup()

if __name__ == "__main__":
    main()