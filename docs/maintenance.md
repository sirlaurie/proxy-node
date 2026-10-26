# 维护检查

安装 `requirements-dev.txt` 后，在仓库根目录运行：

```bash
ruff check .
ruff format --check .
ruff check --stdin-filename panel-update/systemd-run.py - < panel-update/systemd-run
python3 -m unittest discover -s tests -v
```

`systemd-run` 是无 `.py` 扩展名的可执行入口，所以单独指定 Python 文件类型检查。
