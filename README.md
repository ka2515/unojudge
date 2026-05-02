# 專案名稱：114 資科賽自動評分系統 (Judge)

### 🚀 快速操作
* **本機上傳**：`gpush "備註"`
* **遠端部署**：`ssh pi5 "~/bin/update_judge.sh"`
* **預設管理帳密**：`admin` / `123456`

### 🌐 環境資訊
* **主控機 IP**：`172.16.112.237` (帳號: aqcg)
* **硬體配置**：Raspberry Pi 5 + PIM699 (NVMe SSD)
* **主要路徑**：評分腳本位於 `~/bin/`，答案檔位於 `~/data/`

### 🛠️ 依賴套件
* Python 3.11+, OpenCV, Pandas (處理名單)
