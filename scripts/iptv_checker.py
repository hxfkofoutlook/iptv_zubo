#!/usr/bin/env python3
"""
IPTV源检测脚本 - 修正版，输出格式优化
"""

import os
import re
import json
import time
import requests
import concurrent.futures
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Optional

# ===============================
# 配置区
# ===============================

# 目标省份运营商与组播地址映射
TARGETS = [
    ("北京", "移动", "228.1.1.128:8001"),
    ("北京", "联通", "239.3.1.238:8001"),
    ("北京", "电信", "225.1.8.36:8002"),
    ("湖南", "电信", "239.76.253.100:9000"),
    ("上海", "电信", "233.18.204.51:5140"),
    ("广东", "电信", "239.77.0.112:5146"),
    ("海南", "电信", "239.253.64.14:5140"),
    ("四川", "电信", "239.94.0.60:5140"),
    ("重庆", "电信", "235.254.197.237:7980"),
    ("河北", "联通", "239.253.92.154:6011"),
    ("河北", "电信", "239.254.200.174:6000"),
]

# GitHub仓库列表
REPOS = [
    "kakaxi-1/zubo",
    "IPTV520/zubo",
    "a52948/zubo",
    "AimerJansen/zubo",
    "caliph21/zubo",
    "cgj555/zubo",
    "Francis-228/zubo",
    "Niming-G/FOFA-IPTV",
    "moonkeyhoo/zubo",
    "QQ1000COM/zubo",
    "us8888/zubo",
]

# 测试配置
REQUEST_TIMEOUT = 10
TEST_TIMEOUT = 20
MAX_WORKERS = 10
MAX_IPS_PER_TARGET = 500
OUTPUT_FILE = "iptv.json"

# ===============================
# GitHub API函数
# ===============================

def fetch_repo_files(repo: str) -> Optional[List[Dict]]:
    """获取仓库ip目录下的文件列表"""
    api_url = f"https://api.github.com/repos/{repo}/contents/ip"
    headers = {'User-Agent': 'IPTV-Scanner'}
    
    if 'GITHUB_TOKEN' in os.environ:
        headers['Authorization'] = f"token {os.environ['GITHUB_TOKEN']}"
    
    try:
        resp = requests.get(api_url, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403:
            print(f"  警告: {repo} 访问被限制")
        else:
            print(f"  警告: {repo} 返回状态码 {resp.status_code}")
    except Exception as e:
        print(f"  错误: 获取 {repo} 失败: {e}")
    
    return None

def is_target_match(filename: str, province: str, isp: str) -> bool:
    """检查文件名是否匹配目标省份和运营商"""
    name = filename.replace('.txt', '').replace(' ', '')
    province_in_name = province in name
    isp_in_name = isp in name
    return province_in_name and isp_in_name

def extract_ips_from_url(download_url: str) -> Set[str]:
    """从下载链接提取IP:端口"""
    ips = set()
    try:
        resp = requests.get(download_url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            lines = resp.text.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', line):
                        ips.add(line)
    except Exception as e:
        print(f"    下载失败: {e}")
    
    return ips

# ===============================
# 测速函数
# ===============================

def check_connectivity(ip_port: str) -> tuple:
    """检查IP:PORT是否可达"""
    test_url = f"http://{ip_port}/"
    
    try:
        start_time = time.time()
        response = requests.head(test_url, timeout=3, allow_redirects=True)
        latency = time.time() - start_time
        
        if response.status_code < 500:
            return True, latency
        else:
            return False, latency
    except Exception:
        return False, None

def test_stream_speed(ip_port: str, multicast_addr: str) -> Optional[Dict]:
    """测试流媒体速度"""
    test_url = f"http://{ip_port}/rtp/{multicast_addr}"
    
    try:
        start_time = time.time()
        total_bytes = 0
        max_bytes = 32768
        
        with requests.get(test_url, stream=True, timeout=TEST_TIMEOUT) as response:
            if response.status_code >= 400:
                return None
            
            chunk_size = 8192
            for chunk in response.iter_content(chunk_size=chunk_size):
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes >= max_bytes:
                    break
        
        download_time = time.time() - start_time
        
        if download_time == 0 or total_bytes == 0:
            return None
        
        speed_kbps = (total_bytes / 1024) / download_time
        
        return {
            'ip_port': ip_port,
            'speed_kbps': round(speed_kbps, 2),
            'download_time': round(download_time, 2),
            'test_url': test_url
        }
    except Exception:
        return None

def complete_speed_test_workflow(ip_list: List[str], multicast_addr: str) -> List[Dict]:
    """完整的测速工作流"""
    if not ip_list:
        return []
    
    # 步骤1: 连通性检查
    print(f"    连通性检查: {len(ip_list)}个IP")
    reachable_ips = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(check_connectivity, ip): ip for ip in ip_list}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            is_connected, latency = future.result()
            if is_connected:
                reachable_ips.append((ip, latency))
    
    print(f"    可达IP: {len(reachable_ips)}个")
    
    if not reachable_ips:
        return []
    
    # 步骤2: 速度测试
    print(f"    速度测试: {len(reachable_ips)}个IP")
    speed_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(test_stream_speed, ip, multicast_addr): (ip, latency) 
            for ip, latency in reachable_ips[:50]  # 限制测试数量
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            ip, latency = future_to_ip[future]
            result = future.result()
            
            if completed % 10 == 0 or completed == len(future_to_ip):
                print(f"      进度: {completed}/{len(future_to_ip)}")
            
            if result:
                # 合并结果
                merged_result = {
                    'ip_port': ip,
                    'speed_kbps': result['speed_kbps'],
                    'latency_ms': round(latency * 1000, 2) if latency else 0,
                    'test_url': result['test_url']
                }
                speed_results.append(merged_result)
    
    # 按速度排序
    speed_results.sort(key=lambda x: x['speed_kbps'], reverse=True)
    return speed_results

def save_results(results: Dict):
    """保存结果到JSON文件"""
    output_data = {
        "update_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "update_timestamp": int(time.time()),
        "total_sources": len(results),
        "total_streams": sum(len(ips) for ips in results.values()),
        "sources": results
    }
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    
    print(f"🎉 结果已保存到 {OUTPUT_FILE}")
    print(f"   总计: {output_data['total_streams']} 个高速IPTV源")

def main():
    print("🚀 IPTV源检测流程开始")
    print("=" * 60)
    
    # 步骤1: 从所有仓库收集IP
    print("📦 从GitHub仓库收集IP文件中...")
    
    ip_collections = defaultdict(set)
    
    for repo in REPOS:
        print(f"\n处理仓库: {repo}")
        files = fetch_repo_files(repo)
        
        if not files:
            continue
        
        txt_files = [f for f in files if f['type'] == 'file' and f['name'].endswith('.txt')]
        
        for file_info in txt_files:
            filename = file_info['name']
            
            for province, isp, _ in TARGETS:
                if is_target_match(filename, province, isp):
                    print(f"  ✅ 匹配到: {filename} -> {province}{isp}")
                    
                    ips = extract_ips_from_url(file_info['download_url'])
                    if ips:
                        key = (province, isp)
                        ip_collections[key].update(ips)
                        print(f"    提取到 {len(ips)} 个IP")
                    break
    
    print(f"\n✅ IP收集完成")
    print(f"   找到 {len(ip_collections)} 个目标组合")
    
    for (province, isp), ips in ip_collections.items():
        print(f"   {province}{isp}: {len(ips)} 个IP")
    
    # 步骤2: 对每个组合进行测试
    print("\n🧪 开始IP连通性和速度测试...")
    final_results = {}
    
    for (province, isp), ip_set in ip_collections.items():
        multicast = next((addr for p, i, addr in TARGETS if p == province and i == isp), None)
        if not multicast:
            print(f"  警告: 未找到 {province}{isp} 的组播地址，跳过")
            continue
        
        ip_list = list(ip_set)
        print(f"\n  处理 {province}{isp}: {len(ip_list)}个IP")
        
        if not ip_list:
            continue
        
        speed_results = complete_speed_test_workflow(ip_list, multicast)
        
        if speed_results:
            top_2 = speed_results[:2]
            
            # 修正输出格式：分开存储ip和组播地址
            final_results[f"{province}{isp}"] = [
                {
                    "ip": item['ip_port'],  # 存储ip:port
                    "multicast": multicast,  # 存储组播地址
                    "speed_kbps": item['speed_kbps'],
                    "latency_ms": item['latency_ms']
                }
                for item in top_2
            ]
            
            print(f"    ✅ 找到 {len(top_2)} 个高速源")
            for i, item in enumerate(top_2, 1):
                print(f"      第{i}名: {item['speed_kbps']} KB/s, 延迟: {item['latency_ms']}ms")
        else:
            print(f"    ❌ 没有可用的IP")
    
    # 步骤3: 保存结果
    save_results(final_results)
    
    print("\n" + "=" * 60)
    print("🎉 程序执行完成")
    print("=" * 60)

if __name__ == "__main__":
    main()
