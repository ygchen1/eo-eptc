import json
import os
import pickle
import gc
import subprocess
import gzip
from multiprocessing import Pool, cpu_count


tcp_local_port = ['7890', '10801', '10802', '10803', '10804', '10805']
tcp_local_c2s_ip_dst = ['10.14.10.36', '10.14.10.37', '10.14.10.38', '10.14.10.39', '10.14.10.40',
    '10.14.50.141', '10.14.50.142', '10.14.50.143', '10.14.50.144', '10.14.50.145']
tcp_proxy_port = ['7870', '7880', '8100', '443', '8121', '8122', '8123', '8124']
tcp_proxy_c2s_ip_src = tcp_local_c2s_ip_dst

quic_local_port = ['443']
quic_local_c2s_ip_src = ['192.168.101.2', '192.168.102.2', '192.168.103.2', '192.168.104.2', '192.168.105.2']
quic_proxy_port = ['8121', '8122', '8123', '8124']
quic_proxy_c2s_ip_dst = ['10.14.50.151', '10.14.50.152', '10.14.50.153', '10.14.50.154', '10.14.50.155']

ip_range = tcp_local_c2s_ip_dst + quic_local_c2s_ip_src + quic_proxy_c2s_ip_dst

def traffic_type_cs(ip_src, ip_dst, src_port, dst_port, dataset_type):
    # determine the traffic_type, client_port, and direction info
    if dataset_type == 'tcp':
        if src_port in tcp_local_port or dst_port in tcp_local_port:
            traffic_type = 'local'
            if ip_dst in tcp_local_c2s_ip_dst:
                client_port = src_port
                cs = 'c2s'
            elif ip_src in tcp_local_c2s_ip_dst:
                client_port = dst_port
                cs = 's2c'
            else:
                raise KeyError
        elif src_port in tcp_proxy_port or dst_port in tcp_proxy_port:
            traffic_type = 'proxy'
            if ip_src in tcp_proxy_c2s_ip_src:
                client_port = src_port
                cs = 'c2s'
            elif ip_dst in tcp_proxy_c2s_ip_src:
                client_port = dst_port
                cs = 's2c'
            else:
                raise KeyError
        else:
            raise KeyError

    elif dataset_type == 'quic':
        if src_port in quic_local_port or dst_port in quic_local_port:
            traffic_type = 'local'
            if ip_src in quic_local_c2s_ip_src:
                client_port = src_port
                cs = 'c2s'
            elif ip_dst in quic_local_c2s_ip_src:
                client_port = dst_port
                cs = 's2c'
            else:
                raise KeyError
        elif src_port in quic_proxy_port or dst_port in quic_proxy_port:
            traffic_type = 'proxy'
            if ip_dst in quic_proxy_c2s_ip_dst:
                client_port = src_port
                cs = 'c2s'
            elif ip_src in quic_proxy_c2s_ip_dst:
                client_port = dst_port
                cs = 's2c'
            else:
                raise KeyError
    else:
        raise KeyError

    return traffic_type, client_port, cs


def my_obj_pairs_hook(json_dict):
    result = {}
    count = {}
    for key, val in json_dict:
        if key in count:
            count[key] = 1 + count[key]
        else:
            count[key] = 1
        if key in result:
            if count[key] > 2:
                result[key].append(val)
            else:
                result[key] = [result[key], val]
        else:
            result[key] = val
    return result


def parse_pcap_name(file_name):
    file_name_split = file_name.replace('ok-', '').replace('.pcapng', '').split('-')
    site_class = file_name_split[1]
    repeat_time = file_name_split[3]
    site_index = file_name_split[5]
    return site_class, repeat_time, site_index


def parse_pcap(dataset_type, proxy_type, file_name, pcap_file_path, pcap_pk_path):

    site_class, repeat_time, site_index = parse_pcap_name(file_name)

    if os.path.exists(pcap_pk_path):
        return
    print(file_name)

    tshark_json_command = 'tshark -r ' + pcap_file_path + ' -V -T json'
    tshark_process = subprocess.Popen(tshark_json_command, shell=True, stdout=subprocess.PIPE, bufsize=-1)
    try:
        tshark_output, _ = tshark_process.communicate(timeout=1200)
    except subprocess.TimeoutExpired:
        tshark_process.kill()
        print("Tshark timeout, process killed.")
        print("pcap_file_path faild")
        return
    tshark_output, _ = tshark_process.communicate()
    tshark_result = json.loads(tshark_output.decode(encoding='UTF-8', errors='ignore'),
                               object_pairs_hook=my_obj_pairs_hook)

    streams = dict()
    google_related_streams_id = []

    for packet in tshark_result:
        packet = packet['_source']['layers']

        if 'frame' in packet:
            frame_num = packet['frame']['frame.number']

            # check time_epoch or time_relative with tshark version and usage
            # TODO: check
            timestamp = packet['frame']['frame.time_relative']
            timestamp_abs = packet['frame']['frame.time_epoch']
            frame_len = packet['frame']['frame.len']

            if 'ip' in packet:
                ip_src = packet['ip']['ip.src']
                ip_dst = packet['ip']['ip.dst']

                if ip_src in ip_range or ip_dst in ip_range:
                    # streams
                    if 'tcp' in packet:
                        stream_num = packet['tcp']['tcp.stream']
                        payload_len = packet['tcp']['tcp.len']
                        tcp_syn = packet['tcp']['tcp.flags_tree']['tcp.flags.syn']
                        tcp_ack = packet['tcp']['tcp.flags_tree']['tcp.flags.ack']
                        tcp_push = packet['tcp']['tcp.flags_tree']['tcp.flags.push']

                        # port extraction
                        src_port = packet['tcp']['tcp.srcport']
                        dst_port = packet['tcp']['tcp.dstport']

                        traffic_type, client_port, cs = traffic_type_cs(ip_src, ip_dst, src_port, dst_port, dataset_type)

                        # check retransmission
                        retransmission_flag = False
                        if '_ws.malformed' in packet:
                            retransmission_flag = True
                        if 'tcp.analysis' in packet['tcp']:
                            if 'tcp.analysis.flags' in packet['tcp']['tcp.analysis']:
                                if isinstance(packet['tcp']['tcp.analysis']['tcp.analysis.flags'], dict):
                                    flags = [packet['tcp']['tcp.analysis']['tcp.analysis.flags']]
                                elif isinstance(packet['tcp']['tcp.analysis']['tcp.analysis.flags'], list):
                                    flags = packet['tcp']['tcp.analysis']['tcp.analysis.flags']
                                else:
                                    raise KeyError
                                for flag in flags:
                                    if '_ws.expert' in flag:
                                        if isinstance(flag['_ws.expert'], dict):
                                            ws_experts = [flag['_ws.expert']]
                                        elif isinstance(flag['_ws.expert'], list):
                                            ws_experts = flag['_ws.expert']
                                        else:
                                            raise KeyError

                                        for ws_expert in ws_experts:
                                            if '_ws.expert.message' in ws_expert:
                                                if isinstance(ws_expert['_ws.expert.message'], str):
                                                    expert_messages = [ws_expert['_ws.expert.message']]
                                                elif isinstance(ws_expert['_ws.expert.message'], list):
                                                    expert_messages = ws_expert['_ws.expert.message']
                                                else:
                                                    raise KeyError

                                                for expert_message in expert_messages:
                                                    if 'retransmission' in expert_message:
                                                        retransmission_flag = True
                                                    elif 'out-of-order' in expert_message:
                                                        retransmission_flag = True

                        if retransmission_flag:
                            continue

                        # init new stream
                        if file_name + '_' + str(client_port) + '_' + 'tcp' not in streams:
                            # init the stream
                            streams[file_name + '_' + str(client_port) + '_' + 'tcp'] = {'proxy_type': proxy_type,
                                'site_class': site_class, 'repeat_time': repeat_time, 'traffic_type': traffic_type,
                                'site_index': site_index, 'file_name': file_name, 'stream_num': stream_num,
                                'start_timestamp_abs': timestamp_abs,'start_timestamp': timestamp, 'end_timestamp': '',
                                'frame_num': 0, 'size': 0, 'ip': (ip_src, ip_dst),
                                'client_port': client_port, 'tcp': [], 'tls':[], 'http': []}

                        # count the frame number and the size
                        streams[file_name + '_' + str(client_port) + '_' + 'tcp']['frame_num'] += 1
                        streams[file_name + '_' + str(client_port) + '_' + 'tcp']['size'] += int(frame_len)
                        streams[file_name + '_' + str(client_port) + '_' + 'tcp']['end_timestamp'] = timestamp

                        tcp_info = {'frame_num': frame_num, 'timestamp': timestamp, 'frame_len': frame_len,
                                       'ip_src': ip_src, 'ip_dst': ip_dst, 'payload_len': payload_len, 'cs': cs,
                                       'src_port': src_port, 'dst_port': dst_port,'tcp_syn':tcp_syn, 'tcp_ack': tcp_ack, 'tcp_push': tcp_push}
                        streams[file_name + '_' + str(client_port) + '_' + 'tcp']['tcp'].append(tcp_info)

                        if int(payload_len) > 0:
                            # http
                            if 'http' in packet:
                                if 'http.request' in packet['http'] or 'http.response' in packet['http']:
                                    http = (frame_num, packet['http'])
                                    if 'http.request.full_uri' in packet['http']:
                                        if isinstance(packet['http']['http.request.full_uri'], str):
                                            if 'google' in packet['http']['http.request.full_uri'] or 'firefox' in packet['http']['http.request.full_uri'] or 'mozilla' in packet['http']['http.request.full_uri']:
                                                google_related_streams_id.append(file_name + '_' + str(client_port) + '_' + 'tcp')
                                    streams[file_name + '_' + str(client_port) + '_' + 'tcp']['http'].append(http)
                                if 'ocsp' in packet:
                                    google_related_streams_id.append(file_name + '_' + str(client_port) + '_' + 'tcp')
                            # tls
                            if 'tls' in packet:
                                if isinstance(packet['tls'], dict):
                                    tls_list = [packet['tls']]
                                else:
                                    tls_list = packet['tls']
                                for tls in tls_list:
                                    if 'tls.record' in tls:
                                        if isinstance(tls['tls.record'], dict):
                                            tls_record_list = [tls['tls.record']]
                                        else:
                                            tls_record_list = tls['tls.record']
                                        for tls_record in tls_record_list:
                                            if 'tls.record.content_type' in tls_record:
                                                content_type = tls_record['tls.record.content_type']
                                                # TLS handshake
                                                if content_type == '22':
                                                    if 'tls.handshake' in tls_record:
                                                        if 'tls.handshake.type' in tls_record['tls.handshake']:
                                                            content_type += ':' + tls_record['tls.handshake']['tls.handshake.type']
                                            # TLS 1.3
                                            elif 'tls.record.opaque_type' in tls_record:
                                                content_type = tls_record['tls.record.opaque_type']
                                            else:
                                                content_type = None
                                            if 'tls.record.length' not in tls_record:
                                                continue

                                            payload_length = int(tls_record['tls.record.length'])
                                            # add timestamp to tls
                                            tls_tmp = (frame_num, cs, content_type, payload_length, timestamp)
                                            streams[file_name + '_' + str(client_port) + '_' + 'tcp']['tls'].append(tls_tmp)

                    elif 'udp' in packet:
                        stream_num = packet['udp']['udp.stream']
                        payload_len = packet['udp']['udp.length']

                        # port extraction
                        src_port = packet['udp']['udp.srcport']
                        dst_port = packet['udp']['udp.dstport']

                        traffic_type, client_port, cs = traffic_type_cs(ip_src, ip_dst, src_port, dst_port, dataset_type)

                        # init new stream
                        if file_name + '_' + str(client_port) + '_' + 'udp' not in streams:
                            # init the stream
                            streams[file_name + '_' + str(client_port) + '_' + 'udp'] = {'proxy_type': proxy_type,
                                'site_class': site_class, 'repeat_time': repeat_time, 'traffic_type': traffic_type,
                                'site_index': site_index, 'file_name': file_name, 'stream_num': stream_num,
                                'start_timestamp': timestamp, 'end_timestamp': '', 'frame_num': 0, 'size': 0, 'ip': (ip_src, ip_dst),
                                'client_port': client_port, 'udp': [], 'quic':[]}

                        # count the frame number and the size
                        streams[file_name + '_' + str(client_port) + '_' + 'udp']['frame_num'] += 1
                        streams[file_name + '_' + str(client_port) + '_' + 'udp']['size'] += int(frame_len)
                        streams[file_name + '_' + str(client_port) + '_' + 'udp']['end_timestamp'] = timestamp

                        udp_info = {'frame_num': frame_num, 'timestamp': timestamp, 'frame_len': frame_len,
                                       'ip_src': ip_src, 'ip_dst': ip_dst, 'payload_len': payload_len, 'cs': cs,
                                       'src_port': src_port, 'dst_port': dst_port}
                        streams[file_name + '_' + str(client_port) + '_' + 'udp']['udp'].append(udp_info)

                        if int(payload_len) > 0:
                            # quic
                            if 'quic' in packet:
                                if isinstance(packet['quic'], dict):
                                    quic_list = [packet['quic']]
                                else:
                                    quic_list = packet['quic']
                                for quic in quic_list:
                                    payload_length = None
                                    if 'quic.packet_length' in quic:
                                        payload_length = int(quic['quic.packet_length'])

                                    head_form = None
                                    if 'quic.header_form' in quic:
                                        head_form = quic['quic.header_form']
                                    elif 'quic.short' in quic:
                                        if 'quic.header_form' in quic['quic.short']:
                                            head_form = quic['quic.short']['quic.header_form']
                                    # change: add head_form and timestamp
                                    quic_tmp = (frame_num, cs, payload_length, head_form, timestamp)
                                    streams[file_name + '_' + str(client_port) + '_' + 'udp']['quic'].append(quic_tmp)


    # remove background flows
    for stream_id in list(set(google_related_streams_id)):
        streams.pop(stream_id)

    del tshark_result
    gc.collect()

    with gzip.open(pcap_pk_path, 'wb') as fp:
        pickle.dump(streams, fp)


if __name__ == '__main__':
    pool = Pool(cpu_count())
    cwd = os.getcwd()
    data_pcapng_dir = 'data_pcapng'
    data_pk_dir = 'data_pk'
    # proxy_dir can be 'tcp_ss_clean', 'tcp_vmess_clean', 'tcp_trojan_clean', 'tcp_vless_clean',
    # 'quic_ss_clean', 'quic_vmess_clean', 'quic_trojan_clean', 'quic_vless_clean'
    proxy_dirs = ['tcp_ss_clean']

    for proxy_dir in proxy_dirs:
        dataset_type = proxy_dir.split('_')[0]
        proxy_type = proxy_dir.split('_')[1]

        sub_data_pcapng_dir = os.path.join(data_pcapng_dir, proxy_dir)
        sub_data_pk_dir = os.path.join(data_pk_dir, proxy_dir)
        os.makedirs(sub_data_pk_dir, exist_ok=True)

        file_names = list(os.listdir(sub_data_pcapng_dir))
        file_names.sort(key=lambda file_name:os.path.getsize(os.path.join(sub_data_pcapng_dir, file_name)))

        for file_name in file_names:
            pcap_file_path = os.path.join(cwd, sub_data_pcapng_dir, file_name)
            pcap_pk_path = os.path.join(cwd, sub_data_pk_dir, file_name + '.pk.gz')

            pool.apply_async(parse_pcap, (dataset_type, proxy_type, file_name, pcap_file_path, pcap_pk_path,))
            # parse_pcap(dataset_type, proxy_type, file_name, pcap_file_path, pcap_pk_path)
    pool.close()
    pool.join()
