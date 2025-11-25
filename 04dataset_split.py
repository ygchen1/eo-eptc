import pickle
import os
import gzip


if __name__ == '__main__':
    cache_dir = 'data_cache'
    # dataset_file can be 'tcp_ss_all.cache.pk.gz', 'tcp_vmess_all.cache.pk.gz', 'tcp_trojan_all.cache.pk.gz', 'tcp_vless_all.cache.pk.gz',
    # 'quic_ss_all.cache.pk.gz', 'quic_vmess_all.cache.pk.gz', 'quic_trojan_all.cache.pk.gz', 'quic_vless_all.cache.pk.gz'
    dataset_files = ['tcp_ss_all.cache.pk.gz']

    # devide one by one
    seq2seq_indexes = [2*x+1 for x in range(30)]
    seq2seq_index_map = {index: seq2seq_indexes.index(index) for index in seq2seq_indexes}

    seqclassify_indexes = [2*x for x in range(30)]
    seqclassify_index_map = {index: seqclassify_indexes.index(index) for index in seqclassify_indexes}
    print('seq2seq_index_map')
    print(seq2seq_index_map)
    print('seqclassify_index_map')
    print(seqclassify_index_map)

    for dataset_file in dataset_files:
        if not dataset_file.endswith('_all.cache.pk.gz'):
            continue

        dataset_file_path = os.path.join(cache_dir, dataset_file)
        with gzip.open(dataset_file_path, 'rb') as fp:
            streams = pickle.load(fp)
        print('Load Dataset Finished')

        seq2seq_data = {}
        seqclassify_data = {}
        for key in streams:
            stream = streams[key]
            site_index = int(stream['site_index'])
            if site_index in seq2seq_indexes:
                new_site_index = str(seq2seq_index_map[site_index])
                stream['site_index'] = new_site_index
                seq2seq_data[key] = stream
            elif site_index in seqclassify_indexes:
                new_site_index = str(seqclassify_index_map[site_index])
                stream['site_index'] = new_site_index
                seqclassify_data[key] = stream
            else:
                raise KeyError

        seq2seq_cache_path = os.path.join(cache_dir, dataset_file.replace('all.cache.pk.gz', 'seq2seq.cache.pk.gz'))
        with gzip.open(seq2seq_cache_path, 'wb') as fp:
            pickle.dump(seq2seq_data, fp)

        seqclassify_cache_path = os.path.join(cache_dir, dataset_file.replace('all.cache.pk.gz', 'seqclassify.cache.pk.gz'))
        with gzip.open(seqclassify_cache_path, 'wb') as fp:
            pickle.dump(seqclassify_data, fp)