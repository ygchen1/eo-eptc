import argparse


def ArgumentParser():
    parser = argparse.ArgumentParser(description="Transformer Model Configuration")

    # Training parameters
    parser.add_argument("--learning_rate", default=0.005, type=float,
                        help="learning rate")
    parser.add_argument("--batch_size", default=128, type=int,
                        help="training and eval batch size")
    parser.add_argument("--seed", default=1, type=int,
                        help="torch seed")
    parser.add_argument("--cuda", default=True, type=bool,
                        help="whether to use cuda")
    parser.add_argument("--gpu_id", default=3, type=int,
                        help="gpu choose")

    # Ttransformer  parameters
    parser.add_argument("--num_hiddens", default=32, type=int,
                        help="transformer hidden size")
    parser.add_argument("--num_layers", default=3, type=int,
                        help="number of transformer layers")
    parser.add_argument("--dropout", default=0.05, type=float,
                        help="dropout rate")
    parser.add_argument("--num_steps", default=64, type=int,
                        help="sequence length")
    parser.add_argument("--ffn_num_input", default=32, type=int,
                        help="FFN input size")
    parser.add_argument("--ffn_num_hiddens", default=64, type=int,
                        help="FFN hidden size")
    parser.add_argument("--num_heads", default=4, type=int,
                        help="number of attention heads")
    parser.add_argument("--key_size", default=32, type=int,
                        help="key size")
    parser.add_argument("--query_size", default=32, type=int,
                        help="query size")
    parser.add_argument("--value_size", default=32, type=int,
                        help="value size")

    parser.add_argument("--norm_shape", default=32, type=int,
                        help="normalization shape (will be converted to list)")

    parser.add_argument("--packet_limits", default=32, type=int,
                        help="classification packet limits")

    return parser.parse_args()