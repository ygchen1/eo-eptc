import os
import pickle
import gzip
from multiprocessing import Pool, cpu_count


def quic_rough_match(local_stream, proxy_stream_stat):
    local_stream_begin_timestamp = local_stream[3]
    local_stream_end_timestamp = local_stream[4]
    local_stream_duration = local_stream[5]

    proxy_stream_candidate = []
    for i, proxy_stream in enumerate(proxy_stream_stat):
        proxy_stream_begin_timestamp = proxy_stream[3]
        if proxy_stream_begin_timestamp > local_stream_begin_timestamp and proxy_stream_begin_timestamp < local_stream_begin_timestamp + 1:
            proxy_stream_candidate.append((i, proxy_stream))

    if len(proxy_stream_candidate) > 0:
        proxy_stream_candidate.sort(key=lambda item:abs(item[1][3] - local_stream_begin_timestamp)+abs(item[1][4] - local_stream_end_timestamp)+abs(item[1][5] - local_stream_duration))
        proxy_stream_index = proxy_stream_candidate[0][0]
        proxy_stream = proxy_stream_stat.pop(proxy_stream_index)
    else:
        return None

    return proxy_stream


def quic_streams_match(pcap_pk_file_path, match_pk_file_path):
    if os.path.exists(match_pk_file_path):
        return
        # pass
    print(pcap_pk_file_path)

    # read the log and pcap file
    with gzip.open(pcap_pk_file_path, 'rb') as fp:
        streams = pickle.load(fp)

    # make stream statistic
    local_stream_stat = []
    proxy_stream_stat = []
    for stream_id, stream in streams.items():
        client_port = stream['client_port']
        traffic_type = stream['traffic_type']
        proxy_type = stream['proxy_type']

        c2s_cnt = 0
        s2c_cnt = 0
        if traffic_type == 'local':
            start_time = float(stream['start_timestamp'])
            end_time = float(stream['end_timestamp'])
            duration = end_time - start_time
            ip = stream['ip']
            if 'udp' not in stream:
                continue
            for packet in stream['udp']:
                if packet['cs'] == 'c2s':
                    c2s_cnt += int(packet['payload_len'])
                else:
                    s2c_cnt += int(packet['payload_len'])

            local_stream_stat.append([stream_id, int(client_port), traffic_type, start_time, end_time, duration, ip ,c2s_cnt, s2c_cnt])

        elif traffic_type == 'proxy':
            if proxy_type == 'ss':
                start_time = float(stream['start_timestamp'])
                end_time = float(stream['end_timestamp'])
                duration = end_time - start_time
                ip = stream['ip']
                if 'udp' not in stream:
                    continue
                for packet in stream['udp']:
                    if packet['cs'] == 'c2s':
                        c2s_cnt += int(packet['payload_len'])
                    else:
                        s2c_cnt += int(packet['payload_len'])

                proxy_stream_stat.append([stream_id, int(client_port), traffic_type, start_time, end_time, duration, ip, c2s_cnt, s2c_cnt])
            elif proxy_type in ['trojan', 'vless', 'vmess']:
                start_time = float(stream['start_timestamp'])
                end_time = float(stream['end_timestamp'])
                duration = end_time - start_time
                ip = stream['ip']
                if 'tcp' not in stream:
                    continue
                for packet in stream['tcp']:
                    if packet['cs'] == 'c2s':
                        c2s_cnt += int(packet['payload_len'])
                    else:
                        s2c_cnt += int(packet['payload_len'])

                proxy_stream_stat.append(
                    [stream_id, int(client_port), traffic_type, start_time, end_time, duration, ip, c2s_cnt, s2c_cnt])

    # match local streams and proxy streams
    local_stream_stat.sort(key=lambda item: (item[3], item[5]))
    proxy_stream_stat.sort(key=lambda item: (item[3], item[5]))
    match_results = []
    while(len(local_stream_stat) > 0):
        local_stream = local_stream_stat.pop(0)
        proxy_stream = quic_rough_match(local_stream, proxy_stream_stat)
        if proxy_stream:
            match_results.append((local_stream, proxy_stream))

    # match streams
    match_streams = dict()
    for match_result in match_results:
        local_stream_id = match_result[0][0]
        local_port = match_result[0][1]
        proxy_stream_id = match_result[1][0]
        proxy_port = match_result[1][1]

        match_streams[local_stream_id] = {'local_port': local_port, 'local': streams[local_stream_id],
                                          'proxy_port': proxy_port, 'proxy': streams[proxy_stream_id]}

    # save matched results
    with gzip.open(match_pk_file_path, 'wb') as fp:
        pickle.dump(match_streams, fp)
    print(pcap_pk_file_path, 'done')
    return


def tcp_strict_sequence_match(A, B, delta, tolerance=3):

    i, j = 0, 0

    while i < len(A) and j < len(B):
        if abs(A[i] - (B[j] + delta)) <= tolerance:
            i += 1
            j += 1
        elif j + 1 < len(B) and abs(A[i] - (B[j] + B[j + 1] + delta)) <= tolerance:
            i += 1
            j += 2
        else:
            return False

    return i == len(A)


def tcp_streams_match(pcap_pk_file_path, match_pk_file_path):
    if os.path.exists(match_pk_file_path):
        return
    print(pcap_pk_file_path)

    # read the log and pcap file
    with gzip.open(pcap_pk_file_path, 'rb') as fp:
        streams = pickle.load(fp)

    # make stream statistic
    local_stream_stat = []
    proxy_stream_stat = []
    for stream_id, stream in streams.items():
        client_port = stream['client_port']
        traffic_type = stream['traffic_type']
        proxy_type = stream['proxy_type']
        c2s_valid_size = 0
        s2c_valid_size = 0
        c2s_valid_frame_num = 0
        s2c_valid_frame_num = 0
        c2s_length_seq = []
        s2c_length_seq = []

        bias = {
            "ss": 34,
            "trojan": 17,
            "vless": 17,
            "vmess": 35,
        }
        bia = bias[proxy_type]

        c2s_cnt = 0
        s2c_cnt = 0
        if traffic_type == 'local':
            for packet in stream['tcp']:
                if int(packet['payload_len']) > 0:
                    if packet['cs'] == 'c2s':
                        if packet['tcp_push'] == '1':
                            c2s_cnt += int(packet['payload_len'])
                            c2s_valid_frame_num += 1
                            c2s_length_seq.append(c2s_cnt)
                            c2s_cnt = 0
                        else:
                            c2s_cnt += int(packet['payload_len'])
                    else:
                        if packet['tcp_push'] == '1':
                            s2c_cnt += int(packet['payload_len'])
                            s2c_valid_frame_num += 1
                            s2c_length_seq.append(s2c_cnt)
                            s2c_cnt = 0
                        else:
                            s2c_cnt += int(packet['payload_len'])

            if len(c2s_length_seq) > 0 and len(s2c_length_seq) > 0:
                c2s_length_seq = c2s_length_seq
                s2c_length_seq = s2c_length_seq
                c2s_valid_size = sum(c2s_length_seq)
                s2c_valid_size = sum(s2c_length_seq)
                local_stream_stat.append([stream_id, int(client_port), traffic_type, c2s_valid_size, s2c_valid_size, c2s_length_seq, s2c_length_seq])

        elif traffic_type == 'proxy':
            if proxy_type == 'ss':
                for packet in stream['tcp']:
                    if int(packet['payload_len']) > 0:
                        if packet['cs'] == 'c2s':
                            if packet['tcp_push'] == '1':
                                c2s_cnt += int(packet['payload_len'])
                                c2s_valid_frame_num += 1
                                c2s_length_seq.append(c2s_cnt)
                                c2s_cnt = 0
                            else:
                                c2s_cnt += int(packet['payload_len'])
                        else:
                            if packet['tcp_push'] == '1':
                                s2c_cnt += int(packet['payload_len'])
                                s2c_valid_frame_num += 1
                                s2c_length_seq.append(s2c_cnt)
                                s2c_cnt = 0
                            else:
                                s2c_cnt += int(packet['payload_len'])


                if len(c2s_length_seq) > 0 and len(s2c_length_seq) > 0:
                    c2s_valid_size = sum(c2s_length_seq)
                    s2c_valid_size = sum(s2c_length_seq)
                    c2s_length_seq = [x for x in c2s_length_seq[2:-1]]
                    proxy_stream_stat.append([stream_id, int(client_port), traffic_type, c2s_valid_size, s2c_valid_size, c2s_length_seq, s2c_length_seq])

            elif proxy_type == 'trojan':
                for message in stream['tls']:  # tls = (frame_num, cs, content_type, message_length, payload_length)
                    if message[2] == '23':
                        if message[1] == 'c2s':
                            c2s_valid_frame_num += 1
                            c2s_length_seq.append(message[3])
                        else:
                            s2c_valid_frame_num += 1
                            s2c_length_seq.append(message[3])

                if len(c2s_length_seq) > 0 and len(s2c_length_seq) > 0:
                    c2s_valid_size = sum(c2s_length_seq)
                    s2c_valid_size = sum(s2c_length_seq)
                    c2s_length_seq = [x for x in c2s_length_seq[2:-1]]
                    proxy_stream_stat.append([stream_id, int(client_port), traffic_type, c2s_valid_size, s2c_valid_size, c2s_length_seq, s2c_length_seq])

            elif proxy_type == 'vless':
                for message in stream['tls']:  # tls = (frame_num, cs, content_type, message_length, payload_length)
                    if message[2] == '23':
                        if message[1] == 'c2s':
                            c2s_valid_frame_num += 1
                            c2s_length_seq.append(message[3])
                        else:
                            s2c_valid_frame_num += 1
                            s2c_length_seq.append(message[3])

                if len(c2s_length_seq) > 0 and len(s2c_length_seq) > 0:
                    c2s_valid_size = sum(c2s_length_seq)
                    s2c_valid_size = sum(s2c_length_seq)
                    c2s_length_seq = [x for x in c2s_length_seq[2:-1]]
                    proxy_stream_stat.append([stream_id, int(client_port), traffic_type, c2s_valid_size, s2c_valid_size, c2s_length_seq, s2c_length_seq])

            elif proxy_type == 'vmess':
                for message in stream['tls']:  # tls = (frame_num, cs, content_type, payload_length)
                    if message[2] == '23':
                        if message[1] == 'c2s':
                            c2s_valid_frame_num += 1
                            c2s_length_seq.append(message[3])
                        else:
                            s2c_valid_frame_num += 1
                            s2c_length_seq.append(message[3])

                if len(c2s_length_seq) > 0 and len(s2c_length_seq) > 0:
                    c2s_valid_size = sum(c2s_length_seq)
                    s2c_valid_size = sum(s2c_length_seq)
                    c2s_length_seq = [x for x in c2s_length_seq[2:-1]]
                    proxy_stream_stat.append([stream_id, int(client_port), traffic_type, c2s_valid_size, s2c_valid_size, c2s_length_seq, s2c_length_seq])

    # match local streams and proxy streams
    local_stream_stat.sort(key=lambda item: item[1])
    proxy_stream_stat.sort(key=lambda item: item[1])
    match_results = []
    left_stat = []

    # match based on two length seq
    while len(local_stream_stat) > 0:
        local_stream = local_stream_stat.pop(0)
        find_flag = False
        find_index = None
        for i in range(len(proxy_stream_stat)):
            # c2s length seq
            if tcp_strict_sequence_match(proxy_stream_stat[i][5], local_stream[5][1:], bia) and proxy_stream_stat[i][4] / local_stream[4] > 1.0 and proxy_stream_stat[i][4] / local_stream[4] < 1.5:
                find_flag = True
                find_index = i
                break
        if find_flag:
            proxy_stream = proxy_stream_stat.pop(find_index)
            match_results.append((local_stream, proxy_stream))
        else:
            left_stat.append(local_stream)

    left_stat.extend(proxy_stream_stat)

    # match streams
    match_streams = dict()
    for match_result in match_results:
        local_stream_id = match_result[0][0]
        local_port = match_result[0][1]
        proxy_stream_id = match_result[1][0]
        proxy_port = match_result[1][1]

        match_streams[local_stream_id] = {'local_port': local_port, 'local': streams[local_stream_id],
                                          'proxy_port': proxy_port, 'proxy': streams[proxy_stream_id]}

    # save matched results
    with gzip.open(match_pk_file_path, 'wb') as fp:
        pickle.dump(match_streams, fp)
    print(pcap_pk_file_path, 'done')
    return


if __name__ == '__main__':

    pool = Pool(cpu_count())
    data_pk_dir = 'data_pk'
    # sub_folder can be 'tcp_ss_clean', 'tcp_vmess_clean', 'tcp_trojan_clean', 'tcp_vless_clean',
    # 'quic_ss_clean', 'quic_vmess_clean', 'quic_trojan_clean', 'quic_vless_clean'
    sub_folders = ['tcp_ss_clean']

    for sub_folder in sub_folders:
        traffic_type = sub_folder.split('_')[0]
        sub_dataset_dir = os.path.join(data_pk_dir, sub_folder)
        file_names = os.listdir(sub_dataset_dir)
        file_name_prefixs = list(
            set([file_name.replace('.pcapng', '').replace('.pk.gz', '').replace('.match', '') for file_name in file_names]))
        file_name_prefixs.sort()

        for file_name in file_name_prefixs:
            pcap_pk_path = os.path.join(sub_dataset_dir, file_name + '.pcapng.pk.gz')
            match_pk_path = os.path.join(sub_dataset_dir, file_name + '.match.pk.gz')

            if traffic_type == 'tcp':
                pool.apply_async(tcp_streams_match, (pcap_pk_path, match_pk_path,))
                # tcp_streams_match(pcap_pk_path,  match_pk_path)
            elif traffic_type == 'quic':
                pool.apply_async(quic_streams_match, (pcap_pk_path, match_pk_path,))
                # quic_streams_match(pcap_pk_path, match_pk_path)
            else:
                raise KeyError
    pool.close()
    pool.join()