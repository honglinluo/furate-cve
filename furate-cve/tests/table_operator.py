from typing import List, Dict, Union, Any
from tests.mysql_connector import MySQLConnector
import re


class TableOperator:
    def __init__(self, table_name: str, connector: MySQLConnector):
        self.table_name = table_name
        self.connector = connector
        self._validate_table()

    @property
    def name(self):
        return self.table_name

    @name.setter
    def name(self, table_name):
        self.table_name = table_name
        self._validate_table()

    @name.deleter
    def name(self):
        self.connector.drop_table(self.table_name)
        del self

    def __del__(self):
        pass

    def _validate_table(self):
        if self.table_name not in self.connector.get_tables():
            raise ValueError(f"Table {self.table_name} not exists")

    def _validate_fields(self, fields: List[str]):
        existing_fields = [col['Field'] for col in
                           self.connector.execute_query(f"DESCRIBE {self.table_name}")]
        invalid = set(fields) - set(existing_fields)
        if invalid:
            raise ValueError(f"Invalid fields: {invalid}")

    def execute_raw_sql(self, sql: str, params: tuple = None) -> Dict[str, Any]:
        """
        执行原始SQL语句并返回结果
        返回格式: {
            'status': bool,
            'data': list/None,
            'rowcount': int,
            'lastrowid': int/None
        }
        """
        sql = sql.strip()
        is_select = re.match(r'^SELECT', sql, re.IGNORECASE)

        try:
            if is_select:
                return {
                    'status': True,
                    'data': self.connector.execute_query(sql, params),
                    'rowcount': len(self.connector.execute_query(sql, params)),
                    'lastrowid': None
                }
            else:
                affected = self.connector.execute_update(sql, params)
                return {
                    'status': True,
                    'data': None,
                    'rowcount': affected,
                    'lastrowid': self.connector.conn.cursor().lastrowid
                }
        except Exception as e:
            return {
                'status': False,
                'error': str(e),
                'data': None,
                'rowcount': 0,
                'lastrowid': None
            }

    def build_select_sql(self, fields: List[str],
                         conditions: Dict[str, Union[str, int]] = None) -> str:
        self._validate_fields(fields)
        sql = f"SELECT {', '.join(fields)} FROM {self.table_name}"
        if conditions:
            where = ' AND '.join([f"{k}=%s" for k in conditions.keys()])
            sql += f" WHERE {where}"
        return sql

    def batch_insert(self, data: List[Dict]) -> int:
        if not data:
            return 0
        fields = list(data[0].keys())
        self._validate_fields(fields)

        placeholders = ', '.join(['%s'] * len(fields))
        sql = f"INSERT INTO {self.table_name} ({', '.join(fields)}) VALUES ({placeholders})"

        with self.connector.conn.cursor() as cursor:
            cursor.executemany(sql, [tuple(item.values()) for item in data])
            return cursor.rowcount

    def batch_update(self, updates: Dict[str, Dict[str, Union[str, int]]],
                     key_field: str = 'id') -> int:
        case_statements = []
        params = []
        key_values = []

        for key_val, fields in updates.items():
            key_values.append(key_val)
            for field, value in fields.items():
                case_statements.append(f"{field}=CASE WHEN {key_field}=%s THEN %s ELSE {field} END")
                params.extend([key_val, value])

        sql = f"UPDATE {self.table_name} SET {', '.join(case_statements)} WHERE {key_field} IN ({', '.join(['%s'] * len(key_values))})"
        params.extend(key_values)

        with self.connector.conn.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.rowcount

    def batch_delete(self, ids: List[Union[str, int]],
                     key_field: str = 'id') -> int:
        placeholders = ', '.join(['%s'] * len(ids))
        sql = f"DELETE FROM {self.table_name} WHERE {key_field} IN ({placeholders})"

        with self.connector.conn.cursor() as cursor:
            cursor.execute(sql, ids)
            return cursor.rowcount
