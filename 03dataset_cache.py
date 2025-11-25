import os
import pickle
import gzip
from multiprocessing import Pool, cpu_count


def dataset_read(traffic_type, proxy_type, pk_path):
    with gzip.open(pk_path, 'rb') as fp:
        match_streams = pickle.load(fp)
    fp.close()

    valid_streams = dict()
    for id, match_stream in match_streams.items():
        local_stream = match_stream['local']
        if traffic_type == 'tcp':
            local = local_stream['tcp']
            local_length_seq = [
                [packet['cs'], packet['payload_len'], packet['tcp_syn'], packet['tcp_ack'], packet['tcp_push']]
                for packet in local]
        elif traffic_type == 'quic':
            local = local_stream['udp']
            local_length_seq = [[packet['cs'], packet['payload_len']] for packet in local]
        else:
            raise KeyError

        proxy_stream = match_stream['proxy']
        if traffic_type == 'tcp' and proxy_type == 'ss':
            proxy = proxy_stream['tcp']
            proxy_length_seq = [
                [packet['cs'], packet['payload_len'], packet['tcp_syn'], packet['tcp_ack'], packet['tcp_push']] for
                packet in proxy]
        elif traffic_type == 'tcp' and proxy_type in ['trojan', 'vmess', 'vless']:
            proxy = proxy_stream['tls']
            # TODO: check the usage
            proxy_length_seq = [list(message)[1:] for message in proxy]
        elif traffic_type == 'quic' and proxy_type == 'ss':
            proxy = proxy_stream['udp']
            proxy_length_seq = [[packet['cs'], packet['payload_len']] for packet in proxy]
        elif traffic_type == 'quic' and proxy_type in ['trojan', 'vmess', 'vless']:
            proxy = proxy_stream['tls']
            indices = [1, 3]
            proxy_length_seq = [[list(packet)[i] for i in indices] for packet in proxy if list(packet)[2] == '23']
        else:
            raise KeyError

        valid_streams[id] = {'proxy_type': local_stream['proxy_type'], 'site_class': local_stream['site_class'],
                             'repeat_time': local_stream['repeat_time'], 'site_index': local_stream['site_index'],
                             'file_name': local_stream['file_name'], 'stream_num': local_stream['stream_num'],
                             'local_length_seq': local_length_seq, 'proxy_length_seq': proxy_length_seq}

    print('read', pk_path, 'successfully')

    return valid_streams


if __name__ == '__main__':
    pool = Pool(cpu_count())
    dataset_dir = 'data_pk'
    cache_dir = 'data_cache'
    os.makedirs(cache_dir, exist_ok=True)
    # sub_folder can be 'tcp_ss_clean', 'tcp_vmess_clean', 'tcp_trojan_clean', 'tcp_vless_clean',
    # 'quic_ss_clean', 'quic_vmess_clean', 'quic_trojan_clean', 'quic_vless_clean'
    sub_folders = ['tcp_ss_clean']

    for sub_folder in sub_folders:
        print('processing', sub_folder)

        traffic_type = sub_folder.split('_')[0]
        proxy_type = sub_folder.split('_')[1]

        pool = Pool(cpu_count())
        process_results = []
        sub_dataset_dir = os.path.join(dataset_dir, sub_folder)
        file_names = os.listdir(sub_dataset_dir)
        file_names.sort()
        for file_name in file_names:
            if file_name.endswith('.match.pk.gz'):
                match_pk_path = os.path.join(sub_dataset_dir, file_name)
                # dataset_read(traffic_type, proxy_type, match_pk_path)
                process_results.append(pool.apply_async(dataset_read, (traffic_type, proxy_type, match_pk_path, )))
        pool.close()
        pool.join()

        # read results
        streams = dict()
        sorted_streams = dict()
        for result in process_results:
            sub_streams = result.get()
            for stream_id, stream in sub_streams.items():
                streams[stream_id] = stream

        # sort stream ids
        stream_ids = list(streams.keys())
        stream_ids.sort()
        for stream_id in stream_ids:
            sorted_streams[stream_id] = streams[stream_id]

        cache_path = os.path.join(cache_dir, f'{traffic_type}_{proxy_type}_all.cache.pk.gz')
        with gzip.open(cache_path, 'wb') as fp:
            pickle.dump(sorted_streams, fp)
        fp.close()