#!/usr/bin/env python3
"""
IPTV源检测脚本 - 修正版，输出格式优化
"""

import os
import re
import json
import time
import requests
import subprocess
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
    ("广东", "电信", "239.77.0.84:5146"),
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
    "UserLinYa/zubo",
    "wangxiaobo23/newzubo",
    "zhaochunen/zubo",
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
    """从下载链接提取IP:端口，如果超过20个，只取最后20个"""
    ips = set()
    try:
        resp = requests.get(download_url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            lines = resp.text.split('\n')
            valid_ips = []
            
            # 收集所有有效的IP
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', line):
                        valid_ips.append(line)
            
            # 检查IP数量并处理
            if len(valid_ips) > 20:
                print(f"    (从 {len(valid_ips)} 个IP中取了最后20个)")
                valid_ips = valid_ips[-20:]  # 只取最后20个
            # 如果正好20个或更少，不显示提示
            
            # 添加到集合中（自动去重）
            ips.update(valid_ips)
            
    except Exception as e:
        print(f"    下载失败: {e}")
    
    return ips

# ===============================
# 测速函数 - 修改为第一个脚本的逻辑
# ===============================

def check_stream(url: str, timeout: int = 5) -> bool:
    """检查流是否可播放，使用ffprobe检测（第一个脚本的逻辑）"""
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-show_streams", "-i", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2
        )
        return b"codec_type" in result.stdout
    except Exception:
        return False

def test_stream_playable(ip_port: str, multicast_addr: str) -> Optional[Dict]:
    """测试流媒体是否可播放（使用第一个脚本的逻辑）"""
    test_url = f"http://{ip_port}/rtp/{multicast_addr}"
    
    try:
        start_time = time.time()
        
        # 使用第一个脚本的ffprobe检测逻辑
        is_playable = check_stream(test_url, timeout=TEST_TIMEOUT)
        
        download_time = time.time() - start_time
        
        if is_playable:
            return {
                'ip_port': ip_port,
                'playable': True,
                'latency_ms': round(download_time * 1000, 2),
                'test_url': test_url
            }
        else:
            return None
    except Exception:
        return None

def complete_speed_test_workflow(ip_list: List[str], multicast_addr: str) -> List[Dict]:
    """完整的测速工作流"""
    if not ip_list:
        return []
    
    # 直接使用ffprobe检测流是否可播放（第一个脚本的逻辑）
    print(f"    可播放性测试: {len(ip_list)}个IP")
    playable_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(test_stream_playable, ip, multicast_addr): ip 
            for ip in ip_list[:50]  # 限制测试数量
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            ip = future_to_ip[future]
            result = future.result()
            
            if completed % 10 == 0 or completed == len(future_to_ip):
                print(f"      进度: {completed}/{len(future_to_ip)}")
            
            if result:
                playable_results.append(result)
    
    print(f"    可播放IP数量: {len(playable_results)}个")
    
    # 按延迟排序（延迟越低越好）
    playable_results.sort(key=lambda x: x['latency_ms'])
    return playable_results

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
    print(f"   总计: {output_data['total_streams']} 个可播放的IPTV源")

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
    print("\n🧪 开始IP可播放性测试...")
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
        
        playable_results = complete_speed_test_workflow(ip_list, multicast)
        
        if playable_results:
            top_2 = playable_results[:2]
            
            # 修正输出格式：分开存储ip和组播地址
            final_results[f"{province}{isp}"] = [
                {
                    "ip": item['ip_port'],  # 存储ip:port
                    "multicast": multicast,  # 存储组播地址
                    "latency_ms": item['latency_ms']
                }
                for item in top_2
            ]
            
            print(f"    ✅ 找到 {len(top_2)} 个可播放源")
            for i, item in enumerate(top_2, 1):
                print(f"      第{i}名: 延迟 {item['latency_ms']}ms")
        else:
            print(f"    ❌ 没有可播放的IP")
    
    # 步骤3: 保存结果
    save_results(final_results)
    
    print("\n" + "=" * 60)
    print("🎉 程序执行完成")
    print("=" * 60)

if __name__ == "__main__":
    main()
