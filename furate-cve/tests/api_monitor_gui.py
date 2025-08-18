import tkinter as tk
from tkinter import ttk
from threading import Thread
from queue import Queue
from datetime import datetime
from DrissionPage import ChromiumPage


class APIMonitorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("API Monitor v2.1")
        self._setup_ui()
        self.page = ChromiumPage()
        self.message_queue = Queue()
        self.monitoring = False

    def _setup_ui(self):
        # 状态栏
        self.status_var = tk.StringVar(value="🟢 Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var)
        status_bar.pack(fill=tk.X)

        # 控制面板
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)
        ttk.Button(control_frame, text="Start", command=self.start_monitor).grid(row=0, column=0)
        ttk.Button(control_frame, text="Stop", command=self.stop_monitor).grid(row=0, column=1)

        # 结果展示树
        self.result_tree = ttk.Treeview(self.root, columns=('Time', 'Method', 'Status', 'URL'), show='headings')
        self.result_tree.heading('Time', text='Time')
        self.result_tree.heading('Method', text='Method')
        self.result_tree.heading('Status', text='Status')
        self.result_tree.heading('URL', text='URL')
        self.result_tree.pack(fill=tk.BOTH, expand=True)

        # 详情面板
        self.detail_text = tk.Text(self.root, height=10)
        self.detail_text.pack(fill=tk.X)
        self.result_tree.bind('<<TreeviewSelect>>', self._show_detail)

    def start_monitor(self):
        if not self.monitoring:
            self.monitoring = True
            self.page.listen.start('.*')  # 监听所有接口
            Thread(target=self._monitor_apis, daemon=True).start()
            self.status_var.set("🔴 Monitoring...")
            self.root.after(100, self._process_queue)

    def stop_monitor(self):
        self.monitoring = False
        self.status_var.set("🟢 Stopped")

    def _monitor_apis(self):
        while self.monitoring:
            try:
                packet = self.page.listen.wait(timeout=1)
                if packet:
                    self.message_queue.put({
                        'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                        'method': packet.request.method,
                        'status': packet.response.status_code,
                        'url': packet.url,
                        'detail': f"{packet.request.headers}\n\n{packet.response.body}"
                    })
            except Exception as e:
                self.message_queue.put({'error': str(e)})

    def _process_queue(self):
        while not self.message_queue.empty():
            data = self.message_queue.get_nowait()
            if 'error' in data:
                self.status_var.set(f"⚠️ {data['error']}")
            else:
                self.result_tree.insert('', 'end', values=(
                    data['time'],
                    data['method'],
                    data['status'],
                    data['url']
                ))
        self.root.after(100, self._process_queue)

    def _show_detail(self, event):
        item = self.result_tree.selection()[0]
        url = self.result_tree.item(item, 'values')[3]
        for i in self.result_tree.get_children():
            if self.result_tree.item(i, 'values')[3] == url:
                detail = next(
                    (d['detail'] for d in list(self.message_queue.queue)
                     if 'detail' in d and d['url'] == url),
                    "No details available"
                )
                self.detail_text.delete(1.0, tk.END)
                self.detail_text.insert(tk.END, detail)
                break

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    monitor = APIMonitorGUI()
    monitor.run()
