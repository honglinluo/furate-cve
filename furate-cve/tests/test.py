from DrissionPage import ChromiumPage
import json
import subprocess
from datetime import datetime
from collections import defaultdict


class APIMonitor:
    def __init__(self):
        self.page = ChromiumPage()
        self.api_records = []
        self.tech_fingerprints = defaultdict(list)

    def start_monitoring(self, target_url):
        """启动接口监控"""
        self.page.set.ignore_certificate_errors()

        self.page.listen.start(".*")  # 监听所有请求
        self.page.get(target_url)

        while True:
            try:
                packet = self.page.listen.wait(timeout=5)
                print(packet)
                if packet:
                    self._process_packet(packet)
                    self._scan_fingerprints(packet.url)
            except Exception as e:
                print(f"监控异常: {e}")
                break

    def _process_packet(self, packet):
        """处理请求数据包"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'method': packet.request.method,
            'url': packet.url,
            'status': packet.response.status_code,
            'request_headers': dict(packet.request.headers),
            'response_headers': dict(packet.response.headers),
            'response_body': self._parse_response(packet.response.body)
        }
        self.api_records.append(record)
        print(f"捕获到API请求: {record['method']} {record['url']}")

    def _scan_fingerprints(self, url):
        """使用Wappalyzer进行指纹识别"""
        try:
            base_url = '/'.join(url.split('/')[:3])
            if base_url not in self.tech_fingerprints:
                result = subprocess.run(
                    ['wappalyzer', base_url],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    tech_data = json.loads(result.stdout)
                    self.tech_fingerprints[base_url] = tech_data
                    print(f"发现新技术指纹: {tech_data.keys()}")
        except Exception as e:
            print(f"指纹识别失败: {e}")

    def _parse_response(self, body):
        """解析响应内容"""
        try:
            return json.loads(body)
        except:
            return str(body)[:1000] if body else ""

    def export_results(self, filename='api_monitor_results.json'):
        """导出监控结果"""
        report = {
            'api_records': self.api_records,
            'fingerprints': dict(self.tech_fingerprints)
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"结果已导出到 {filename}")


if __name__ == '__main__':
    monitor = APIMonitor()
    try:
        monitor.start_monitoring('https://www.baidu.com')
    except KeyboardInterrupt:
        monitor.export_results()
