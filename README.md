# Proxy node stack

为中心 3x-ui 部署可独立运行、可注册回中心面板的 Linux 节点。种子是仓库外的普通目录，含私有面板数据库；不要提交到 Git。目标机需 x86_64、Python 3.12+、Nginx 1.25.1+（含 stream 模块）、Certbot、`python3-yaml` 和 `python3-qrcode`。云防火墙放行 TCP 80/443/24443、UDP 443。

## 新节点

中心机导出目录并通过 SSH 复制仓库和种子（示例登录用户为 `ubuntu`）：

```bash
sudo python3 /home/meta/proxy-node-stack/node/export_seed.py /tmp/oracle-seed
sudo chown -R meta:meta /tmp/oracle-seed
scp -r /home/meta/proxy-node-stack ubuntu@NEW_IP:proxy-node-stack
scp -r /tmp/oracle-seed ubuntu@NEW_IP:oracle-seed
```

SSH 登录目标机，安装依赖、预检并部署（替换域名和 IP）：

```bash
sudo apt install nginx libnginx-mod-stream certbot python3-yaml python3-qrcode
sudo install -d -m 0755 /root/proxy-stack
sudo cp -a ~/proxy-node-stack/. /root/proxy-stack/
sudo python3 /root/proxy-stack/node/migrate.py /home/ubuntu/oracle-seed \
  --domain oracle.example.com --server-ip NEW_IP --check-only
sudo python3 /root/proxy-stack/node/migrate.py /home/ubuntu/oracle-seed \
  --domain oracle.example.com --server-ip NEW_IP
```

失败修复原因后，以完全相同参数增加 `--resume`；不要删除 `/var/lib/proxy-migration/state.json`。把新机令牌安全复制回中心机，再注册并关联已有客户端：

```bash
sudo cp /root/proxy-stack/node-connection.json /home/ubuntu/node-connection.json
sudo chown ubuntu:ubuntu /home/ubuntu/node-connection.json
```

```bash
scp ubuntu@NEW_IP:node-connection.json /tmp/oracle-node-connection.json
sudo python3 /home/meta/proxy-node-stack/node/register_node.py \
  /tmp/oracle-node-connection.json --name oracle --clients iphone mac-mini arch-gateway
```

## 更新

面板内使用“更新面板”按钮。更新 Xray 核心：

```bash
sudo python3 /root/proxy-stack/xray-update/update.py --version latest
```

Xray 自动更新定时器默认关闭；完成 Stash、Happ 等实际客户端验证后，可运行 `sudo systemctl enable --now xray-core-update.timer`。
