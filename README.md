# Welcome to the OSG (Opcode Sequence Graph) repo



        @@            @@        
        @@            @@        
         @@          @@         
          *@@-@@@@+@@#          
           =@@@@@@@@%           
          @@% @@@@ =@@          
   @@    :@@@@@@@@@@@@+    @@   
  @@-@@@.              -@@@:@@  
=@@     @@@@@@@  @@@@@@@     @@%
         @@@@@@  @@@@@@         
  -@@@@@@@@@@@@  @@@@@@@@@@@@=  
 @@:     @@@@@@  @@@@@@     .@@ 
@@   @@%%%@@@@@  @@@@@%%%@@   @@
     @@   -@@@@  @@@@#   @@     
     @@     @@@  @@@     @@     
     @@       #  %       @@     
     @@                  @@     



## This repository includes:
- In the dataset_sha256 folder there are the sha-256 of files used in the paper.
- The LSTM_models.ipynb file contains the main functions to create and train the LSTM-based models described in the paper.
- The GNN_opcode.ipynb file contains the main functions to create and train the GNN model.


### Instructions to extract opcodes, features, create graphs and datasets compatible with the proposed solution.
It's necessary to install the Radare2 (https://rada.re/n/radare2.html) to extract the opcodes from files. 

To extract features, creates graphs, and to create instances compatible with the jupyter notebooks, use the /src/single_file_cfg.py file.


### The OSG Dataset

To access the files (hash for safety purpose) and complementary data visit https://huggingface.co/datasets/areeberg/OSG-academic .
