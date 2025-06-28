import pdb

import r2pipe
from opcodes import Opcode_str
from spektral.data import Dataset, DisjointLoader, Graph
import networkx as nx
from collections import Counter
import numpy as np
from sklearn.preprocessing import OneHotEncoder
from spektral.transforms import AdjToSpTensor, LayerPreprocess
from spektral.layers import GCNConv

def opcodes_stt(path_file:str, limit=None):
    def opcodes_stt(path_file: str, limit=None):
        """
        Extracts a sequence of opcode mnemonics from the functions in a binary file using r2pipe.

        This function analyzes the control flow graph (CFG) of the specified binary file and collects
        opcode mnemonics from all functions whose names contain "entry" or "fcn". The opcodes are
        concatenated into a single string, separated by spaces, up to a specified limit.

        Args:
            path_file (str): The path to the binary file to analyze.
            limit (int, optional): The maximum number of opcodes to extract. If None, extracts all available opcodes.

        Returns:
            str: A space-separated string of opcode mnemonics extracted from the binary's functions.
        """
    r2 = r2pipe.open(path_file)
    r2.cmd("aaa")
    cfg = r2.cmdj("agCj")
    flist = r2.cmdj('aflj')
    list_functions = []
    stt = ""
    num_commands = 0
    for i in flist:
        fname = i['name']
        if "entry" in fname:
            list_functions.append(fname)
        if "fcn" in fname:
            list_functions.append(fname)

    for fun in list_functions:
        command = "agj "+fun
        cfg = r2.cmdj(command)
        try:
            blocks = cfg[0]['blocks']
        except:
            continue
        for block in blocks:
            for opc in block['ops']:
                if len(stt) == 0:
                    stt = opc['opcode'].split(' ')[0]
                    num_commands += 1
                else:
                    try:
                        stt = stt+' '+opc['opcode'].split(' ')[0]
                        num_commands += 1
                    except:
                        pass
                if num_commands > limit:
                    r2.quit()
                    return stt
    r2.quit()
    return stt


def opcodes_sttv2(path_file:str, limit=None):
    def opcodes_sttv2(path_file: str, limit=None):
        """
        Extracts and concatenates the first opcode of each instruction from the control flow graph (CFG) of functions
        in a binary file using radare2, up to a specified limit.

        Args:
            path_file (str): The path to the binary file to analyze.
            limit (int, optional): The maximum number of opcodes to extract. If None, extracts all available opcodes.

        Returns:
            str: A space-separated string of opcode mnemonics extracted from the binary's functions, up to the specified limit.

        Notes:
            - Requires the `r2pipe` Python package and radare2 installed.
            - The function analyzes each function in the binary, traverses its basic blocks, and collects the first word
              (mnemonic) of each opcode.
            - If the limit is reached, the function returns the collected opcodes immediately.
            - If an error occurs while processing a function or block, it is silently skipped.
        """
    r2 = r2pipe.open(path_file)
    r2.cmd("aaa")
    cfg = r2.cmdj("agCj")
    stt = ""
    num_commands = 0

    for fun in cfg:
        command = "agj "+fun['name']
        cfg = r2.cmdj(command)
        try:
            blocks = cfg[0]['blocks']
        except:
            continue
        for block in blocks:
            for opc in block['ops']:
                if len(stt) == 0:
                    stt = opc['opcode'].split(' ')[0]
                    num_commands += 1
                else:
                    try:
                        stt = stt+' '+opc['opcode'].split(' ')[0]
                        num_commands += 1
                    except:
                        pass
                if num_commands > limit:
                    r2.quit()
                    return stt
    r2.quit()
    return stt

def create_features(opcodes_sequence: str):
    """
    Converts a space-separated string of opcode names into a list of corresponding opcode values.

    Parameters:
        opcodes_sequence (str): A string containing opcode names separated by spaces. 
                                The last element is ignored.

    Returns:
        list: A list of values corresponding to the opcodes found in the Opcode_str enumeration.

    Notes:
        - Only opcodes present in the Opcode_str enumeration are included in the result.
        - Assumes that Opcode_str is an Enum with opcode names as members and their values as the desired output.
    """
    ret_value = list()
    opcodes_split = opcodes_sequence.split(" ")[:-1]
    for opcode in opcodes_split:
        if opcode in Opcode_str.__members__:
            ret_value.append(Opcode_str[opcode].value)
    return ret_value

def create_graph(features):
    """
    Creates a weighted undirected graph from a sequence of features.

    Each unique feature in the input list is added as a node. Edges are created between consecutive features,
    and the weight of each edge corresponds to the number of times the pair appears consecutively in the input.

    Args:
        features (list): A list of features (hashable objects) representing nodes. Edges are formed between consecutive elements.

    Returns:
        networkx.Graph: An undirected graph with nodes for each unique feature and weighted edges representing consecutive occurrences.
    """
    G = nx.Graph()
    unique = list(set(features))
    G.add_nodes_from(unique) #add nodes
    i = 0
    list_edges = []
    while i < (len(features)-1):
        list_edges.append((features[i], features[i+1]))
        i += 1
    res = [(*key, val) for key, val in Counter(list_edges).items()]
    G.add_weighted_edges_from(res)
    return G

# spektral custom dataset class
class Customdataset(Dataset):
    """
    A custom dataset class for handling graph data and corresponding labels.

    This class inherits from the base `Dataset` class and is designed to process
    a list of NetworkX graphs and their associated labels. It converts each graph
    into a format suitable for graph neural network models, extracting node features,
    adjacency matrices, edge lists, and labels.

    Attributes
    ----------
    graph : list
        A list of NetworkX graph objects to be processed.
    labels : list
        A list of labels corresponding to each graph.

    Methods
    -------
    read():
        Processes the input graphs and labels, converting them into a list of
        `Graph` objects with node features, adjacency matrices, edge features,
        and labels.
    """
    
    def __init__(self, graph, labels, **kwargs):
        """
        Initializes the Customdataset with graphs and labels.

        Parameters
        ----------
        graph : list
            List of NetworkX graph objects.
        labels : list
            List of labels corresponding to each graph.
        **kwargs
            Additional keyword arguments passed to the parent Dataset class.
        """
        ...

        """
        Converts the stored graphs and labels into a list of Graph objects.

        For each graph-label pair, extracts:
            - Node features as a NumPy array.
            - Adjacency matrix as a SciPy sparse matrix.
            - Edge list as a NumPy array.
            - Label.

        Returns
        -------
        list
            A list of Graph objects, each containing the processed data for a graph.
        """
        ...
    def __init__(self, graph, labels,  **kwargs):
        self.graph = graph
        self.labels = labels


        super().__init__(**kwargs)

    def read(self):
        output = []
        for gr,lb in zip(self.graph,self.labels):
            A = nx.to_scipy_sparse_matrix(gr)
            X = np.asarray(list(gr.nodes))
            E = np.asarray(list(gr.edges))
            Y = lb
            output.append(
                Graph(x=X.astype("float32"),
                      a=A.astype("float32"),
                      e=E.astype("float32"),
                      y=Y))
        return output



if __name__ == '__main__':
    # Specify the path to the binary file to analyze
    file = 'example.exe' #replace with your binary file path
    
    # Extract a disassembly string (sequence of opcodes) from the file using opcodes_sttv2
    # Limit the number of opcodes to 3000
    dis = opcodes_sttv2(file, limit=3000)
    
    # (Optional) Extract a disassembly string using the alternative function opcodes_stt
    dis1 = opcodes_stt(file, limit=3000)

    # Convert the disassembly string into a list of opcode features (as integers)
    feat = create_features(dis)
    
    # Initialize an empty list to store graphs (for dataset creation)
    listgraph = []
    
    # Create a weighted undirected graph from the opcode features
    Gr = create_graph(feat)
    
    # Example label for the graph (e.g., 1 for malware)
    labels = [1]
    
    # Convert the graph's nodes, degrees, and edges to numpy arrays
    npnodes = np.asarray(list(Gr.nodes))
    nodedeg = np.asarray(list(Gr.degree))
    npedges = np.asarray(list(Gr.edges))
    
    # Get the adjacency matrix of the graph (as a sparse matrix and as a dense matrix)
    Adjmatrix = nx.adjacency_matrix(Gr)
    DenseAdjM = Adjmatrix.todense()

    # (In practice, you would have multiple graphs and labels for a dataset)
    # Here, we only use a single graph for demonstration
    
    # Create a Spektral dataset using the custom dataset class
    # Apply LayerPreprocess (for GCNConv) and AdjToSpTensor transforms to the graphs
    dataset = Customdataset(graph=listgraph, labels=labels, transforms=[LayerPreprocess(GCNConv), AdjToSpTensor()])
    
    # Shuffle and split the dataset indices into training, validation, and test sets (80/10/10 split)
    idx = np.random.permutation(len(dataset))
    split_va, split_te = int(0.8*len(dataset)), int(0.9*len(dataset))
    idx_tr, idx_va, idx_te = np.split(idx, [split_va, split_te])
    
    # Select the corresponding data splits
    data_tr = dataset[idx_tr]
    data_va = dataset[idx_va]
    data_te = dataset[idx_te]

    # Create data loaders for each split using DisjointLoader
    # Specify batch size and number of epochs for training loader
    loader_tr = DisjointLoader(data_tr, batch_size=2, epochs=10)
    loader_va = DisjointLoader(data_va, batch_size=2)
    loader_te = DisjointLoader(data_te, batch_size=2)