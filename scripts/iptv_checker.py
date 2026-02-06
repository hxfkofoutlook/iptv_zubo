#!/usr/bin/env python3
"""
IPTV源检测脚本 - 根据灵活匹配规则从GitHub收集并测试IP
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
    "gclgg/zubo",
]

# 测试配置
REQUEST_TIMEOUT = 10
TEST_TIMEOUT = 8
MAX_WORKERS = 15
MAX_IPS_PER_TARGET = 100  # 每个目标最多测试的IP数量
OUTPUT_FILE = "iptv.json"

# ===============================
# 辅助函数
# ===============================

def fetch_repo_files(repo: str) -> Optional[List[Dict]]:
    """获取仓库ip目录下的文件列表"""
    api_url = f"https://api.github.com/repos/{repo}/contents/ip"
    headers = {'User-Agent': 'IPTV-Scanner'}
    
    # 使用GitHub Token避免速率限制
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
    """
    检查文件名是否匹配目标省份和运营商
    规则: 只要同时包含省份关键词和运营商关键词就匹配
    """
    # 移除文件扩展名和空格
    name = filename.replace('.txt', '').replace(' ', '')
    
    # 检查是否同时包含省份和运营商
    # 注意: 省份关键词只需匹配两个字，比如"北京"匹配"北京市"
    # 运营商关键词需要完全匹配
    province_in_name = province in name
    isp_in_name = isp in name
    
    return province_in_name and isp_in_name

def extract_ips_from_url(download_url: str) -> Set[str]:
    """从下载链接提取IP:端口"""
    ips = set()
    try:
        resp = requests.get(download_url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            # 匹配IP:端口格式
            lines = resp.text.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # 简单验证IP:端口格式
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', line):
                        ips.add(line)
    except Exception as e:
        print(f"    下载失败: {e}")
    
    return ips

def test_ip_speed(ip_port: str, multicast_addr: str) -> Optional[Dict]:
    """
    测试单个IP的可用性和速度
    返回包含速度信息的结果字典
    """
    test_url = f"http://{ip_port}/rtp/{multicast_addr}"
    
    try:
        # 第一阶段: 快速HEAD请求检查基本连通性
        start_time = time.time()
        head_resp = requests.head(
            test_url,
            timeout=3,
            allow_redirects=True
        )
        latency = time.time() - start_time
        
        if head_resp.status_code >= 400:
            return None
        
        # 第二阶段: 下载一小段数据测试速度
        chunk_size = 1024 * 8  # 8KB
        speed_start = time.time()
        
        with requests.get(
            test_url,
            stream=True,
            timeout=TEST_TIMEOUT
        ) as resp:
            if resp.status_code >= 400:
                return None
            
            # 读取数据直到达到32KB或超时
            total_bytes = 0
            max_bytes = 1024 * 32  # 32KB
            time_limit = 5  # 5秒限制
            
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if not chunk:
                    break
                    
                total_bytes += len(chunk)
                if total_bytes >= max_bytes or (time.time() - speed_start) > time_limit:
                    break
        
        download_time = time.time() - speed_start
        
        if download_time == 0:
            return None
        
        # 计算速度 (KB/s)
        speed_kbps = (total_bytes / 1024) / download_time
        
        # 计算综合评分 (速度/延迟)
        score = speed_kbps / max(latency, 0.001)
        
        return {
            'url': test_url,
            'ip_port': ip_port,
            'speed_kbps': round(speed_kbps, 2),
            'latency_ms': round(latency * 1000, 2),
            'score': round(score, 2)
        }
        
    except Exception:
        return None

def batch_test_ips(ip_list: List[str], multicast_addr: str) -> List[Dict]:
    """批量测试IP列表"""
    results = []
    
    # 限制测试数量避免耗时过长
    test_ips = ip_list[:MAX_IPS_PER_TARGET]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {
            executor.submit(test_ip_speed, ip, multicast_addr): ip 
            for ip in test_ips
        }
        
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                results.append(result)
    
    return results

def main():
    print("🚀 IPTV源检测流程开始")
    print("=" * 60)
    
    # 步骤1: 从所有仓库收集IP
    print("📦 从GitHub仓库收集IP文件中...")
    
    # 数据结构: {(省份, 运营商): {ip1, ip2...}}
    ip_collections = defaultdict(set)
    
    for repo in REPOS:
        print(f"\n处理仓库: {repo}")
        files = fetch_repo_files(repo)
        
        if not files:
            continue
        
        # 筛选出.txt文件
        txt_files = [f for f in files if f['type'] == 'file' and f['name'].endswith('.txt')]
        
        for file_info in txt_files:
            filename = file_info['name']
            
            # 检查是否匹配任何目标
            for province, isp, _ in TARGETS:
                if is_target_match(filename, province, isp):
                    print(f"  ✅ 匹配到: {filename} -> {province}{isp}")
                    
                    # 下载并提取IP
                    ips = extract_ips_from_url(file_info['download_url'])
                    if ips:
                        key = (province, isp)
                        ip_collections[key].update(ips)
                        print(f"    提取到 {len(ips)} 个IP")
                    break
    
    print(f"\n✅ IP收集完成")
    print(f"   找到 {len(ip_collections)} 个目标组合")
    
    # 显示每个组合收集到的IP数量
    for (province, isp), ips in ip_collections.items():
        print(f"   {province}{isp}: {len(ips)} 个IP")
    
    # 步骤2: 对每个组合进行IP测试和筛选
    print("\n🧪 开始IP连通性和速度测试...")
    final_results = {}
    
    for (province, isp), ip_set in ip_collections.items():
        # 获取对应的组播地址
        multicast = next((addr for p, i, addr in TARGETS if p == province and i == isp), None)
        if not multicast:
            print(f"  警告: 未找到 {province}{isp} 的组播地址，跳过")
            continue
        
        ip_list = list(ip_set)
        print(f"\n  测试 {province}{isp}: {len(ip_list)}个IP")
        
        if not ip_list:
            continue
        
        # 批量测试IP
        test_results = batch_test_ips(ip_list, multicast)
        
        if test_results:
            # 按综合评分排序
            test_results.sort(key=lambda x: x['score'], reverse=True)
            
            # 取最快的2个
            top_results = test_results[:2]
            
            # 格式化结果
            final_results[f"{province}{isp}"] = [
                {
                    "url": item['url'],
                    "speed_kbps": item['speed_kbps'],
                    "latency_ms": item['latency_ms']
                }
                for item in top_results
            ]
            
            print(f"    ✅ 找到 {len(top_results)} 个高速源")
            for i, item in enumerate(top_results, 1):
                print(f"      第{i}名: {item['speed_kbps']} KB/s, 延迟: {item['latency_ms']}ms")
        else:
            print(f"    ❌ 没有可用的IP")
    
    # 步骤3: 保存结果到JSON文件
    output_data = {
        "update_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "update_timestamp": int(time.time()),
        "total_sources": len(final_results),
        "total_streams": sum(len(streams) for streams in final_results.values()),
        "sources": final_results
    }
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    
    print("\n" + "=" * 60)
    print(f"🎉 完成! 结果已保存到 {OUTPUT_FILE}")
    print(f"   覆盖组合: {output_data['total_sources']} 个")
    print(f"   总流数量: {output_data['total_streams']} 个")
    print(f"   更新时间: {output_data['update_time']}")
    print("=" * 60)

if __name__ == "__main__":
    main()
