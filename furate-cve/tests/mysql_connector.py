import json
from typing import Dict, List, Optional
from sqlalchemy import create_engine, MetaData, Table, inspect, Column
from sqlalchemy.engine import URL, Engine
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
from src.utils.logger import Logger

logging = Logger("mysql")


class MySQLConnector:
    def __init__(self, config_path: str = None, **kwargs):
        self._config = self._load_config(config_path, kwargs)
        self._engines: Dict[str, Engine] = {}
        self._current_db: str = ""
        self._metadata = MetaData()
        self._init_engine()

    def _load_config(self, path: str, kwargs: dict) -> dict:
        """加载配置文件"""
        if path:
            with open(path) as f:
                return json.load(f)
        return kwargs

    def _init_engine(self):
        """初始化默认数据库引擎"""
        if not self._config.get('databases'):
            raise ValueError("Missing database configurations")
        self.switch_database(next(iter(self._config['databases'].keys())))

    @property
    def current_db(self) -> str:
        return self._current_db

    def switch_database(self, db_name: str):
        """切换当前数据库"""
        if db_name not in self._config['databases']:
            raise ValueError(f"Database {db_name} not configured")

        if db_name not in self._engines:
            db_config = self._config['databases'][db_name]
            connection_url = URL.create(
                "mysql+pymysql",
                username=db_config['user'],
                password=db_config['password'],
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 3306),
                database=db_config['database']
            )
            self._engines[db_name] = create_engine(
                connection_url,
                pool_size=db_config.get('pool_size', 5),
                pool_recycle=3600,
                future=True
            )

        self._current_db = db_name
        self.Session = sessionmaker(bind=self._engines[db_name])
        logging.info(f"Switched to database: {db_name}")

    def get_table(self, table_name: str) -> Table:
        """获取表对象（自动反射结构）"""
        return Table(
            table_name,
            self._metadata,
            autoload_with=self._engines[self._current_db]
        )

    def create_table(self, table_name: str, columns: List[dict], **kwargs):
        """创建新表"""
        cols = [Column(**col) for col in columns]
        table = Table(table_name, self._metadata, *cols, **kwargs)
        table.create(self._engines[self._current_db])

    def alter_table(self, table_name: str, operations: List[dict]):
        """修改表结构"""
        inspector = inspect(self._engines[self._current_db])
        with self._engines[self._current_db].begin() as conn:
            for op in operations:
                if op['type'] == 'add_column':
                    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {op['spec']}")
                elif op['type'] == 'drop_column':
                    conn.execute(f"ALTER TABLE {table_name} DROP COLUMN {op['column']}")

    def drop_table(self, table_name: str):
        """删除表"""
        self._metadata.tables[table_name].drop(self._engines[self._current_db])

    def get_table_schema(self, table_name: str) -> dict:
        """获取表结构信息"""
        inspector = inspect(self._engines[self._current_db])
        return {
            'columns': inspector.get_columns(table_name),
            'indexes': inspector.get_indexes(table_name),
            'foreign_keys': inspector.get_foreign_keys(table_name)
        }

    @contextmanager
    def session_scope(self):
        """提供事务管理的会话上下文"""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


if __name__ == "__main__":
    # 配置示例
    config = {
        "databases": {
            "main_db": {
                "user": "root",
                "password": "secret",
                "host": "127.0.0.1",
                "database": "production",
                "pool_size": 10
            },
            "log_db": {
                "user": "log_user",
                "password": "log_pass",
                "database": "logs"
            }
        }
    }

    # 使用示例
    connector = MySQLConnector(**config)
    print(connector.get_table_schema("users"))
