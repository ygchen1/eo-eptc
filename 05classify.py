import pickle
import random
import os
import gc
import gzip
from transformer import *
from args import *
from sklearn.model_selection import KFold
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
import numpy as np


def tcp_sequence_feature_reassembly_and_segmentation(stream):
    local_length_sequence = []
    proxy_length_sequence = []

    if stream['proxy_type'] == 'ss':
        local_limit = 8158
    elif stream['proxy_type'] == 'trojan':
        local_limit = 8192
    elif stream['proxy_type'] == 'vmess':
        local_limit = 8174
    elif stream['proxy_type'] == 'vless':
        local_limit = 8192

    c2s_cnt = 0
    s2c_cnt = 0
    for packet in stream['local_length_seq']:
        if int(packet[1]) > 0:
            if packet[0] == 'c2s':
                if packet[4] == '1':
                    c2s_cnt += int(packet[1])
                    local_length_sequence.append(-1 * c2s_cnt)
                    c2s_cnt = 0
                else:
                    c2s_cnt += int(packet[1])
            else:
                if packet[4] == '1':
                    s2c_cnt += int(packet[1])
                    local_length_sequence.append(s2c_cnt)
                    s2c_cnt = 0
                else:
                    s2c_cnt += int(packet[1])
    local_length_sequence = sequence_feature_segmentation(local_length_sequence, local_limit)

    if stream['proxy_type'] == 'ss':
        proxy_limit = 8192

        c2s_cnt = 0
        s2c_cnt = 0
        for packet in stream['proxy_length_seq']:
            if int(packet[1]) > 0:
                if packet[0] == 'c2s':
                    if packet[4] == '1':
                        c2s_cnt += int(packet[1])
                        proxy_length_sequence.append(-1 * c2s_cnt)
                        c2s_cnt = 0
                    else:
                        c2s_cnt += int(packet[1])
                else:
                    if packet[4] == '1':
                        s2c_cnt += int(packet[1])
                        proxy_length_sequence.append(s2c_cnt)
                        s2c_cnt = 0
                    else:
                        s2c_cnt += int(packet[1])
        proxy_length_sequence = sequence_feature_segmentation(proxy_length_sequence, proxy_limit)

    else:
        c2s_cnt = 0
        s2c_cnt = 0
        for packet in stream['proxy_length_seq']:
            if packet[1] == '23':  # tls
                if packet[0] == 'c2s':
                    c2s_cnt += int(packet[2])
                    proxy_length_sequence.append(-1 * (int(packet[2])))
                    c2s_cnt = 0
                else:
                    s2c_cnt += int(packet[2])
                    proxy_length_sequence.append(int(packet[2]))
                    s2c_cnt = 0

    return local_length_sequence, proxy_length_sequence


def sequence_feature_segmentation(seq_a, limit):
    seq_b = split_sequence(seq_a, limit)
    seq_c = [-x for x in seq_b]
    seq_d = split_sequence(seq_c, limit)
    seq_e = [-x for x in seq_d]
    return seq_e


def split_sequence(arr,limit):
    new_arr = []
    count = 0
    for i in range(len(arr)):
        if arr[i] > limit:
            count += arr[i]
        else:
            if count > 0:
                remainder = count % limit
                quotient = count // limit
                for j in range(quotient):
                    new_arr.append(limit)
                if remainder != 0:
                    new_arr.append(remainder)
                count = 0
            new_arr.append(arr[i])
    if count > 0:
        remainder = count % limit
        quotient = count // limit
        for j in range(quotient):
            new_arr.append(limit)
        if remainder != 0:
            new_arr.append(remainder)
    return new_arr


def proxy_handshak_drop(stream, type, proxy_type):
    length_sequence = []

    if proxy_type == 'ss':
        local_c2s = 0
        local_s2c = 0
        proxy_c2s = 1
        proxy_s2c = 9

    elif proxy_type == 'trojan':
        local_c2s = 0
        local_s2c = 0
        proxy_c2s = 1
        proxy_s2c = 6

    elif proxy_type == 'vmess':
        local_c2s = 0
        local_s2c = 0
        proxy_c2s = 3
        proxy_s2c = 7

    elif proxy_type == 'vless':
        local_c2s = 0
        local_s2c = 0
        proxy_c2s = 1
        proxy_s2c = 6

    if type in ['proxy', 'translate']:
        for length in stream[type]:
            if length < 0:
                if proxy_c2s == 0:
                    length_sequence.append(length)
                else:
                    proxy_c2s -= 1
            else:
                if proxy_s2c == 0:
                    length_sequence.append(length)
                else:
                    proxy_s2c -= 1

    elif type in ['local']:
        for length in stream[type]:
            if length < 0:
                if local_c2s == 0:
                    length_sequence.append(length)
                else:
                    local_c2s -= 1
            else:
                if local_s2c == 0:
                    length_sequence.append(length)
                else:
                    local_s2c -= 1

    else:
        return TypeError
    if type in ['proxy', 'translate'] and sum([proxy_c2s, proxy_s2c]) != 0:
        return []
    return length_sequence


def quic_sequence_feature(stream):
    local_length_sequence = []
    proxy_length_sequence = []

    for length in stream['local_length_seq']:
        if int(length[1]) > 0:
            if length[0] == 'c2s':
                local_length_sequence.append(-1 * int(length[1]))
            else:
                local_length_sequence.append(int(length[1]))

    for length in stream['proxy_length_seq']:
        if int(length[1]) > 0:
            if length[0] == 'c2s':
                proxy_length_sequence.append(-1 * int(length[1]))
            else:
                proxy_length_sequence.append(int(length[1]))

    return local_length_sequence, proxy_length_sequence


def code_vector(dataset, traffic_type):
    data_vector = []
    if traffic_type == 'tcp':
        for stream in dataset.values():
            local_sq, proxy_sq = tcp_sequence_feature_reassembly_and_segmentation(stream)
            if len(local_sq) >= 16 and len(proxy_sq) >= 16:
                data_vector.append([local_sq, proxy_sq])
    elif traffic_type == 'quic':
        for stream in dataset.values():
            local_sq, proxy_sq = quic_sequence_feature(stream)
            if len(local_sq) >= 16 and len(proxy_sq) >= 16:
                data_vector.append([local_sq, proxy_sq])
    return data_vector


def rf_data_construct(dataset, train_index, test_index):
    dataset_keys = list(dataset.keys())

    train_data_keys = [dataset_keys[idx] for idx in train_index]
    test_data_keys = [dataset_keys[idx] for idx in test_index]

    train_data = [dataset[key] for key in train_data_keys]
    test_data = [dataset[key] for key in test_data_keys]

    return train_data, test_data


def rf_vector(dataset, dataset_type, args, proxy_type):
    packet_limit = args.packet_limits
    data_vector = []
    if dataset_type == 'train':
        for stream in dataset:
            class_index = int(stream['site_index'])
            length_sequence = proxy_handshak_drop(stream, 'translate', proxy_type)
            if len(length_sequence) < 16:
                continue
            local_length_seq = length_sequence[:packet_limit] + [0] * (packet_limit - len(length_sequence))
            data_vector.append([class_index] + local_length_seq)
    elif dataset_type == 'test':
        for stream in dataset:
            class_index = int(stream['site_index'])
            length_sequence = proxy_handshak_drop(stream, 'proxy', proxy_type)
            if len(length_sequence) < 16:
                continue
            proxy_length_seq = length_sequence[:packet_limit] + [0] * (packet_limit - len(length_sequence))
            data_vector.append([class_index] + proxy_length_seq)
    else:
        raise KeyError
    return data_vector


def ML_RandomForest(train, test):
    train_vec = np.array(train)
    test_vec = np.array(test)

    rf = RandomForestClassifier(n_jobs=-1)
    rf.fit(train_vec[:, 1:], train_vec[:, :1])
    test_pred = rf.predict(test_vec[:, 1:])
    print(classification_report(y_pred=test_pred, y_true=test_vec[:, :1].flatten(), digits=4))


if __name__ == '__main__':
    # configure
    args = ArgumentParser()

    # traffic type can be 'tcp' or 'quic'
    traffic_type = 'tcp'
    # proxy type can be 'ss', 'vmess', 'trojan', 'vless'
    proxy_type = 'ss'

    cache_dir = 'data_cache'
    seq2seq_data_path = os.path.join(cache_dir, f'{traffic_type}_{proxy_type}_seq2seq.cache.pk.gz')
    print('seq2seq_data_path:', seq2seq_data_path)
    classify_data_path = os.path.join(cache_dir, f'{traffic_type}_{proxy_type}_seqclassify.cache.pk.gz')
    print('classify_data_path:', classify_data_path)

    with gzip.open(seq2seq_data_path, 'rb') as fp:
        streams_seq2seq = pickle.load(fp)
    print('Load seq2seq Dataset Finished')

    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        if not args.cuda:
            print("WARNING: You have a CUDA device, so you should probably run with --cuda")
        else:
            torch.cuda.manual_seed(args.seed)
            torch.cuda.set_device(args.gpu_id)
    random.seed(args.seed)

    # data preprocessing
    train_vector = code_vector(streams_seq2seq, traffic_type)
    train_iter, src_vocab, tgt_vocab = load_data(train_vector, args, len(train_vector))

    if traffic_type == 'quic':
        if proxy_type == 'ss':
            num_epochs = 50
        else:
            num_epochs = 2000
    else:
        num_epochs = 150

    encoder = TransformerEncoder(len(src_vocab), args)
    decoder = TransformerDecoder(len(tgt_vocab), args)

    net = EncoderDecoder(encoder, decoder)
    device = try_gpu(args.gpu_id)

    print('start training')
    train_seq2seq(net, train_iter, tgt_vocab, args, device, num_epochs)

    del streams_seq2seq, train_vector, train_iter
    gc.collect()

    with gzip.open(classify_data_path, 'rb') as fp:
        streams_classify = pickle.load(fp)
    print('Load seqclassify Dataset Finished')

    data_set = {}
    total = len(streams_classify)
    pcount = 0
    percent_step = max(1, total // 10)
    last_reported_percent = 0

    for key in streams_classify:
        pcount += 1
        current_percent = (pcount / total) * 100

        if current_percent >= last_reported_percent + 10:
            print(f"Progress: {current_percent:.2f}%")
            last_reported_percent = current_percent

        stream = streams_classify[key]
        if traffic_type == 'tcp':
            local_length_sequence, proxy_length_sequence = tcp_sequence_feature_reassembly_and_segmentation(stream)
        elif traffic_type == 'quic':
            local_length_sequence, proxy_length_sequence = quic_sequence_feature(stream)
        else:
            raise KeyError

        if len(local_length_sequence) >= 16 and len(proxy_length_sequence) >= 16:
            translate_length_sequence_unk = predict_seq2seq(net, local_length_sequence, src_vocab, tgt_vocab, args.num_steps, device)
            translate_length_sequence = unk2zero(translate_length_sequence_unk[0])
            data_set[key] = {}
            data_set[key]['site_class'] = stream['site_class']
            data_set[key]['site_index'] = stream['site_index']
            data_set[key]['local'] = local_length_sequence
            data_set[key]['proxy'] = proxy_length_sequence
            data_set[key]['translate'] = translate_length_sequence

    data_transformed_cache_path = os.path.join(cache_dir, f'{traffic_type}_{proxy_type}_transformed_{num_epochs}.cache.pk.gz')
    print("Progress: 100%")
    with gzip.open(data_transformed_cache_path, 'wb') as fp:
        pickle.dump(data_set, fp)

    kfold = KFold(n_splits=5, shuffle=True, random_state=42)

    splits = kfold.split(data_set)
    for train_index, test_index in splits:
        train_data, test_data = rf_data_construct(data_set, train_index, test_index)
        print('Data Construction Finished')

        # data preprocessing
        train_vector = rf_vector(train_data, 'train', args, proxy_type)
        test_vector = rf_vector(test_data, 'test', args, proxy_type)

        ML_RandomForest(train_vector, test_vector)
