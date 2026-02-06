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
import subprocess
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
PING_TIMEOUT = 2  # ping连通性检查超时时间（秒）
SPEED_TEST_DURATION = 20  # 测速持续时间（秒）
MAX_WORKERS = 10  # 减少并发数，因为测速时间长
MAX_IPS_PER_TARGET = 500  # 减少测试IP数量，因为每个测速1分钟
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
# 测速函数（修改版）
# ===============================

def check_ip_ping(ip: str) -> bool:
    """
    使用ping命令检查IP是否可达
    只检查IP，不检查端口，超时2秒
    """
    try:
        # 提取IP（去掉端口部分）
        ip_address = ip.split(':')[0]
        
        # 使用ping命令检查IP连通性
        # -c 1: 发送1个包
        # -W 2: 等待2秒
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(PING_TIMEOUT), ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT + 1  # 比ping超时多1秒
        )
        
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception) as e:
        return False

def batch_ping_check(ip_list: List[str]) -> List[str]:
    """批量ping检查，返回可达的IP列表"""
    print(f"    Ping检查: {len(ip_list)}个IP")
    
    reachable_ips = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {
            executor.submit(check_ip_ping, ip): ip 
            for ip in ip_list
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            ip = future_to_ip[future]
            
            if completed % 10 == 0 or completed == len(ip_list):
                print(f"      进度: {completed}/{len(ip_list)}")
            
            if future.result():
                reachable_ips.append(ip)
    
    print(f"    Ping检查完成: {len(reachable_ips)}/{len(ip_list)} 个IP可达")
    return reachable_ips

def test_stream_speed_one_minute(ip_port: str, multicast_addr: str) -> Optional[Dict]:
    """
    测试流媒体速度，持续1分钟
    返回下载数据量和平均速度
    """
    test_url = f"http://{ip_port}/rtp/{multicast_addr}"
    
    try:
        total_bytes = 0
        start_time = time.time()
        end_time = start_time + SPEED_TEST_DURATION
        
        print(f"    测速 {ip_port}:", end=" ")
        
        # 设置较长的超时时间
        with requests.get(
            test_url,
            stream=True,
            timeout=SPEED_TEST_DURATION + 10
        ) as response:
            if response.status_code >= 400:
                print("HTTP错误")
                return None
            
            # 持续下载直到时间结束
            chunk_size = 16384  # 16KB块，减少循环次数
            
            try:
                while time.time() < end_time:
                    # 设置读取超时，避免卡住
                    response.raw.sock.settimeout(5.0)
                    
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if not chunk:
                            break
                        
                        total_bytes += len(chunk)
                        
                        # 检查是否达到结束时间
                        if time.time() >= end_time:
                            break
                        
                        # 每下载1MB输出一次进度
                        if total_bytes % (1024*1024) == 0:
                            elapsed = time.time() - start_time
                            speed = total_bytes / elapsed / 1024 if elapsed > 0 else 0
                            print(f"{total_bytes/1024/1024:.1f}MB({speed:.1f}KB/s)", end=" ")
            except (requests.exceptions.Timeout, requests.exceptions.ChunkedEncodingError):
                # 超时或连接中断是正常的
                pass
        
        actual_duration = time.time() - start_time
        
        if actual_duration < 10:  # 至少测试10秒才认为有效
            print("测试时间不足")
            return None
        
        # 计算平均速度
        avg_speed_kbps = (total_bytes / 1024) / actual_duration
        
        print(f"完成: {total_bytes/1024:.0f}KB/{actual_duration:.0f}s = {avg_speed_kbps:.1f}KB/s")
        
        return {
            'ip_port': ip_port,
            'total_bytes': total_bytes,
            'avg_speed_kbps': round(avg_speed_kbps, 2),
            'duration_sec': round(actual_duration, 2),
            'test_url': test_url
        }
        
    except Exception as e:
        print(f"错误: {str(e)[:30]}")
        return None

def complete_speed_test_workflow(ip_list: List[str], multicast_addr: str) -> List[Dict]:
    """完整的测速工作流"""
    if not ip_list:
        return []
    
    # 限制测试数量
    test_ips = ip_list[:MAX_IPS_PER_TARGET]
    
    # 步骤1: ping连通性检查
    reachable_ips = batch_ping_check(test_ips)
    
    if not reachable_ips:
        return []
    
    # 步骤2: 1分钟测速
    print(f"    1分钟测速开始: {len(reachable_ips)}个IP")
    speed_results = []
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {
            executor.submit(test_stream_speed_one_minute, ip, multicast_addr): ip 
            for ip in reachable_ips
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            
            # 显示进度和预估剩余时间
            elapsed = time.time() - start_time
            avg_time_per_ip = elapsed / completed if completed > 0 else SPEED_TEST_DURATION
            remaining = avg_time_per_ip * (len(reachable_ips) - completed)
            
            print(f"      测速进度: {completed}/{len(reachable_ips)}，预估剩余: {remaining/60:.1f}分钟")
            
            result = future.result()
            if result:
                speed_results.append(result)
    
    # 按总下载数据量排序（数据量越大，速度越快越稳定）
    speed_results.sort(key=lambda x: x['total_bytes'], reverse=True)
    
    print(f"    测速完成，找到 {len(speed_results)} 个可用IP")
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
        
        # 使用新的测速流程
        speed_results = complete_speed_test_workflow(ip_list, multicast)
        
        if speed_results:
            # 取下载数据量最大的2个IP
            top_2 = speed_results[:2]
            
            # 修正输出格式：分开存储ip和组播地址
            final_results[f"{province}{isp}"] = [
                {
                    "ip": item['ip_port'],  # 存储ip:port
                    "multicast": multicast,  # 存储组播地址
                    "total_bytes": item['total_bytes'],
                    "avg_speed_kbps": item['avg_speed_kbps'],
                    "duration_sec": item['duration_sec']
                }
                for item in top_2
            ]
            
            print(f"    ✅ 找到 {len(top_2)} 个高速源")
            for i, item in enumerate(top_2, 1):
                print(f"      第{i}名: {item['total_bytes']/1024:.1f}KB, {item['avg_speed_kbps']} KB/s")
        else:
            print(f"    ❌ 没有可用的IP")
    
    # 步骤3: 保存结果
    save_results(final_results)
    
    print("\n" + "=" * 60)
    print("🎉 程序执行完成")
    print("=" * 60)

if __name__ == "__main__":
    main()
