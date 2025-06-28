# Welcome to the OSG (Opcode Sequence Graph) repo

Please, cite the papers properly if used!


    - de Mello, A. R., Lemos, V. G., Barbosa, F. G., & Simoni, E. Malware identification on Portable Executable files using Opcodes Sequence. Page: 8, DOI: 10.21528/CBIC2023-006, https://sbic.org.br/wp-content/uploads/2023/10/pdf/CBIC_2023_paper006.pdf

    - Explainable Boosting Classifier for malware detection and local explanation (Poster), Alexandre Reeberg de Mello, Vitor Gama Lemos, Emilio Simoni 2023/4/3, HotSoS - Hot Topics in the Science of Security, Volume 9, Edition 9, Pages 206, https://sos-vo.org/sites/sos-vo.org/files/2024-02/AR%20FINAL%2023_20231130.pdf



## This repository includes:
- In the dataset_sha256 folder there are the sha-256 of files used in the paper.
- The LSTM_models.ipynb file contains the main functions to create and train the LSTM-based models described in the paper.
- The GNN_opcode.ipynb file contains the main functions to create and train the GNN model.


### Instructions to extract opcodes, features, create graphs and datasets compatible with the proposed solution.
It's necessary to install the Radare2 (https://rada.re/n/radare2.html) to extract the opcodes from files. 

To extract features, creates graphs, and to create instances compatible with the jupyter notebooks, use the /src/single_file_cfg.py file.


### The OSG Dataset

To access the files (hash for safety purpose) and complementary data visit https://huggingface.co/datasets/areeberg/OSG-academic .
