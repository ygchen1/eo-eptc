# EO-EPTC

Implementation of **“EO-EPTC: End-to-End Original Traffic-Based Encrypted Proxy Traffic Classification Framework”**.

This repository provides an end-to-end pipeline for:

- Extracting flow-level features from raw `pcapng` traces  
- Pairing original and proxied traffic  
- Building cached datasets for sequence-to-sequence (seq2seq) and classification tasks  
- Training a seq2seq model and evaluating classification performance  


## 1. Project Structure

- **`01feature_extract.py`**  
  Uses `tshark` to extract required flow features from `pcapng` files.

- **`02flow_merge.py`**  
  Analyzes the extracted features and pairs `original_flow` with `proxied_flow`.

- **`03dataset_cache.py`**  
  Aggregates flow features and generates intermediate dataset cache files.

- **`04dataset_split.py`**  
  Splits the dataset into **seq2seq** and **seqclassify** subsets (e.g., with a 30/30 category ratio).

- **`05classify.py`**  
  1. Trains a seq2seq model on the **seq2seq** dataset  
  2. Uses the trained seq2seq model to “translate” sequence features in the **seqclassify** dataset  
  3. Evaluates the final classification performance  


## 2. System Requirements

- **OS:** Ubuntu ≥ 22.04  
- **Traffic Tool:** `tshark` 4.4.8  
- **Memory:** ≥ 64 GB (recommended)  
- **GPU:** NVIDIA RTX 3090 or better for CUDA acceleration  

Make sure CUDA and appropriate NVIDIA drivers are correctly installed if you plan to use GPU acceleration.


## 3. Python Requirements

Tested with:

- `python==3.10.13`
- `d2l==0.17.5`
- `numpy==2.3.3`
- `scikit_learn==1.3.2`
- `torch==2.0.1`


## 4. Data Cache Format

The **data cache** contains all flow features required for the experiments.  
It consists of multiple records, where **each record is a paired instance of original traffic and proxied traffic**.

Example directory structure:

```text
data_cache/
    ├── tcp_ss_seq2seq.cache.pk.gz
    ├── tcp_ss_seqclassify.cache.pk.gz
    └── ...
````

### 4.1 TCP Flow Representation

Each TCP packet in a flow is represented as a list of attributes, such as:

* Direction (`c2s` / `s2c`)
* Packet length
* SYN flag
* ACK flag
* PUSH flag

Example:

```text
['c2s', '517', '0', '1', '1'],
['s2c', '1460', '0', '1', '0']
```

### 4.2 UDP Flow Representation

Each UDP packet includes:

* Direction
* Packet length

Example:

```text
['c2s', '238'],
['s2c', '122']
```

### 4.3 TLS Message Representation

Each TLS message includes:

* Direction
* Record type (e.g., `22:1`, `22:2`, …)
* Record length

Example:

```text
['c2s', '22:1', '238'],
['s2c', '22:2', '122']
```

These sequences are used as inputs to the seq2seq model and subsequent classification models.


## 5. Usage

**Quick start:**
If you have already downloaded the **`data_cache`** files (e.g., `tcp_ss_seq2seq.cache.pk.gz`, `tcp_ss_seqclassify.cache.pk.gz`), you can **skip Steps 1–4** below and directly run:
>
> ```bash
> python 05classify.py
> ```

